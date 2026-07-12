"""
Agente de IA - Cérebro do Framework de Remediação
Requisito 3: Análise orientada por IA via OpenRouter/Gemini
Requisito 10: Retry com backoff exponencial até 5 tentativas
Requisito 4: Escolher VERSÃO MÍNIMA MITIGADA (same-major strategy)
"""
import os
import json
import time
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

MODEL = os.getenv("AI_MODEL", "google/gemini-2.5-flash")
MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "600"))
TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.1"))
MAX_RETRIES = 5


def get_client():
    api_key = os.getenv("OPEN_ROUTER_API")
    if not api_key:
        raise RuntimeError("OPEN_ROUTER_API não configurada.")
    return OpenAI(api_key=api_key, base_url="https://openrouter.ai/api/v1")


def _call_with_retry(client, prompt):
    """Req 10: retry com backoff exponencial até 5 tentativas."""
    for attempt in range(MAX_RETRIES):
        try:
            response = client.chat.completions.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            delay = 2 ** attempt
            print(f"    ⚠️  Tentativa {attempt + 1} falhou: {e}. Retry em {delay}s...")
            time.sleep(delay)


def get_curated_versions(package_name, ecosystem):
    """
    Consulta banco de dados curado (homologated_versions) para versões aprovadas.
    Retorna lista de versões seguras aprovadas, ordenada.
    
    Req 4: IA deve consultar banco curado para validar versão mínima mitigada.
    """
    try:
        from db import connect_db
        conn = connect_db()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT safe_version, approved_by, notes, approved_at
            FROM homologated_versions
            WHERE package_name = %s AND ecosystem = %s
            ORDER BY approved_at DESC
        """, (package_name, ecosystem))
        
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        if rows:
            return [
                {
                    "version": r[0],
                    "approved_by": r[1],
                    "notes": r[2],
                    "approved_at": str(r[3]) if r[3] else None
                }
                for r in rows
            ]
    except Exception as e:
        print(f"    ⚠️  Erro ao consultar homologated_versions: {e}")
    
    return []


def analisar_pacote(package_name, installed_version, severity, cves,
                     fixed_versions, ecosystem, recommended_version=None):
    """
    Req 3: IA consulta OSV e decide estratégia de remediação para um pacote.
    Req 4: Escolhe VERSÃO MÍNIMA MITIGADA consultando banco curado.
    Consolida múltiplas CVEs do mesmo pacote em uma única decisão (Req 3.5).
    """
    client = get_client()
    
    # Req 4: Consulta versões aprovadas no banco curado
    curated_versions = get_curated_versions(package_name, ecosystem)

    context = {
        "package": package_name,
        "ecosystem": ecosystem,
        "installed_version": installed_version,
        "highest_severity": severity,
        "cves_affected": cves,
        "fixed_versions_available": fixed_versions if isinstance(fixed_versions, list) else [fixed_versions] if fixed_versions else [],
        "recommended_version_from_osv": recommended_version,
        "curated_approved_versions": [v["version"] for v in curated_versions],
        "project_type": "legacy - minimize breaking changes, same-major preferred"
    }

    prompt = f"""You are an autonomous DevSecOps security agent for legacy projects.

Analyze this vulnerability and decide the best remediation strategy.
IMPORTANT: Choose the MINIMUM VERSION that fixes all CVEs (same-major strategy).

Context:
{json.dumps(context, indent=2)}

Decision rules:
1. CRITICAL/HIGH severity with safe version → APPROVE (minimum safe version)
2. Prefer same-major version to avoid breaking changes (e.g., 6.3.0 → 6.5.8, NOT 7.x)
3. If curated_approved_versions exist, prefer one of them
4. If recommended_version_from_osv exists and is same-major, validate it
5. MEDIUM: APPROVE only if update risk is LOW and version is well-tested
6. LOW: IGNORE (not worth the risk)
7. If NO safe remediation exists: MANUAL_REVIEW
8. Consolidate all CVEs of same package into ONE version update

Respond ONLY in valid JSON, no markdown:
{{
  "approved": true,
  "recommended_version": "6.5.8",
  "risk_level": "LOW",
  "strategy": "same-major patch update",
  "justification": "Version 6.5.8 fixes CVEs CVE-2022-29248, etc. No breaking changes in 6.x series. Suitable for legacy projects."
}}"""

    try:
        content = _call_with_retry(client, prompt)

        # Remove markdown fences se presentes
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
        content = content.strip()

        result = json.loads(content)
        return result

    except json.JSONDecodeError as e:
        print(f"    ⚠️  JSON inválido da IA: {e}. Usando fallback.")
    except Exception as e:
        print(f"    ⚠️  Erro na IA: {e}. Usando fallback.")

    # Fallback: prefere curated se existir, caso contrário usa OSV
    safe_ver = None
    if curated_versions:
        safe_ver = curated_versions[0]["version"]  # Já ordenada por approved_at DESC
    elif recommended_version:
        safe_ver = recommended_version
    
    return {
        "approved": severity in ("CRITICAL", "HIGH") and bool(safe_ver),
        "recommended_version": safe_ver,
        "risk_level": "MEDIUM",
        "strategy": "fallback: curated or osv",
        "justification": f"Fallback: severity={severity}, curated={bool(curated_versions)}, version={safe_ver}"
    }


def analisar_lote(vulnerabilidades):
    """
    Req 3: Analisa um lote agrupado por pacote.
    Req 3.5: Consolida múltiplas CVEs do mesmo pacote em uma única decisão.
    Retorna lista de dicts com decisão por pacote.
    """
    # Agrupa por pacote — consolida CVEs (Req 3.5)
    pacotes = {}
    for vuln in vulnerabilidades:
        pkg = vuln["package_name"]
        if pkg not in pacotes:
            pacotes[pkg] = {
                "package_name": pkg,
                "installed_version": vuln["installed_version"],
                "severity": vuln["severity"],
                "cves": [],
                "fixed_version": vuln.get("fixed_version", ""),
                "ecosystem": vuln.get("ecosystem", "PHP"),
                "recommended_version": vuln.get("recommended_version"),
                "ids": []
            }
        pacotes[pkg]["cves"].append(vuln["cve_id"])
        pacotes[pkg]["ids"].append(vuln["id"])

        # Mantém severidade mais alta
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        if sev_order.get(vuln["severity"], 9) < sev_order.get(pacotes[pkg]["severity"], 9):
            pacotes[pkg]["severity"] = vuln["severity"]

    resultados = []
    for pkg, info in pacotes.items():
        print(f"  🧠 IA analisando {pkg} {info['installed_version']} "
              f"(severity: {info['severity']}, CVEs: {len(info['cves'])})...")

        decisao = analisar_pacote(
            package_name=pkg,
            installed_version=info["installed_version"],
            severity=info["severity"],
            cves=info["cves"],
            fixed_versions=info["fixed_version"],
            ecosystem=info["ecosystem"],
            recommended_version=info["recommended_version"]
        )

        status = "✅ APPROVED" if decisao["approved"] else "⏸️  MANUAL_REVIEW"
        print(f"    → {status}: {decisao['justification'][:100]}")

        resultados.append({
            "package_name": pkg,
            "ids": info["ids"],
            "decision": "APPROVED" if decisao["approved"] else "MANUAL_REVIEW",
            "recommended_version": decisao.get("recommended_version"),
            "justification": decisao.get("justification", ""),
            "strategy": decisao.get("strategy", ""),
            "risk_level": decisao.get("risk_level", "MEDIUM")
        })

    return resultados

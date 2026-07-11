"""
Agente de IA - Cérebro do Framework de Remediação
Requisito 3: Análise orientada por IA via OpenRouter/Gemini
Requisito 10: Retry com backoff exponencial até 5 tentativas
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


def analisar_pacote(package_name, installed_version, severity, cves,
                     fixed_versions, ecosystem, recommended_version=None):
    """
    Req 3: IA consulta OSV e decide estratégia de remediação para um pacote.
    Consolida múltiplas CVEs do mesmo pacote em uma única decisão (Req 3.5).
    """
    client = get_client()

    context = {
        "package": package_name,
        "ecosystem": ecosystem,
        "installed_version": installed_version,
        "highest_severity": severity,
        "cves_affected": cves,
        "fixed_versions_available": fixed_versions,
        "recommended_version_from_curated_db": recommended_version,
        "project_type": "legacy PHP - minimize breaking changes, same-major preferred"
    }

    prompt = f"""You are an autonomous DevSecOps security agent for legacy PHP projects.

Analyze this vulnerability and decide the best remediation strategy.

Context:
{json.dumps(context, indent=2)}

Decision rules:
- CRITICAL/HIGH severity: APPROVE if a safe version exists
- Prefer same-major version (e.g., 6.3.0 → 6.5.8, not 7.x) to avoid breaking legacy code
- If recommended_version_from_curated_db is set, validate and prefer it
- MEDIUM: APPROVE only if update risk is LOW
- LOW: IGNORE (not worth the risk)
- If NO safe remediation exists: MANUAL_REVIEW (Req 3.6)
- Consolidate all CVEs of the same package into ONE version update (Req 3.5)

Respond ONLY in valid JSON, no markdown:
{{
  "approved": true,
  "recommended_version": "6.5.8",
  "risk_level": "LOW",
  "strategy": "same-major patch update",
  "justification": "Version 6.5.8 fixes all 5 HIGH CVEs (CVE-2022-29248, etc.) with no breaking changes in the 6.x series. Safe for legacy PHP projects."
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

    # Fallback por severidade
    return {
        "approved": severity in ("CRITICAL", "HIGH") and bool(recommended_version),
        "recommended_version": recommended_version,
        "risk_level": "MEDIUM",
        "strategy": "fallback-rule-based",
        "justification": f"IA indisponível. Fallback: severity={severity}, versão recomendada={recommended_version}"
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

"""
Agente de IA - Cérebro do Framework de Remediação
Usa OpenRouter para analisar vulnerabilidades e decidir a melhor estratégia de correção.
"""
import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


def get_client():
    """Inicializa cliente OpenRouter."""
    api_key = os.getenv("OPEN_ROUTER_API")
    if not api_key:
        raise RuntimeError("OPEN_ROUTER_API não configurada no ambiente.")
    return OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1"
    )


def analisar_vulnerabilidade(package_name, installed_version, severity, cve_id,
                              fixed_versions, ecosystem, recommended_version=None):
    """
    Analisa uma vulnerabilidade e retorna a decisão de remediação via IA.

    Retorna dict com:
      - approved: bool
      - recommended_version: str
      - risk_level: str (LOW/MEDIUM/HIGH)
      - justification: str
      - strategy: str
    """
    client = get_client()

    context = {
        "cve_id": cve_id,
        "package": package_name,
        "ecosystem": ecosystem,
        "installed_version": installed_version,
        "severity": severity,
        "fixed_versions_available": fixed_versions,
        "recommended_version_from_db": recommended_version,
        "focus": "legacy project - minimize breaking changes, same-major preferred"
    }

    prompt = f"""You are an autonomous DevSecOps remediation agent for legacy projects.

Analyze this vulnerability and decide the best remediation strategy.

Context:
{json.dumps(context, indent=2)}

Rules:
- For CRITICAL/HIGH: auto-approve if a safe version exists
- Prefer same-major version updates to avoid breaking changes in legacy code
- If recommended_version_from_db is provided, validate and use it
- For MEDIUM: approve only if risk of update is low
- For LOW: ignore

Respond ONLY in valid JSON:
{{
  "approved": true,
  "recommended_version": "6.5.8",
  "risk_level": "LOW",
  "strategy": "same-major update",
  "justification": "Updating guzzlehttp/guzzle from 6.3.0 to 6.5.8 fixes all 5 HIGH CVEs with no breaking changes in the 6.x series."
}}"""

    try:
        response = client.chat.completions.create(
            model="google/gemini-2.5-flash",
            max_tokens=400,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}]
        )

        content = response.choices[0].message.content or ""

        # Remove markdown code blocks se presentes
        content = content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        content = content.strip()

        result = json.loads(content)
        return result

    except json.JSONDecodeError as e:
        print(f"  ⚠️  IA retornou JSON inválido: {e}")
        # Fallback: decisão baseada em severidade sem IA
        return {
            "approved": severity in ("CRITICAL", "HIGH") and bool(recommended_version),
            "recommended_version": recommended_version,
            "risk_level": "MEDIUM",
            "strategy": "fallback-rule-based",
            "justification": f"Fallback: IA indisponível. Decisão baseada em severity={severity}."
        }
    except Exception as e:
        print(f"  ⚠️  Erro na IA: {e}")
        return {
            "approved": severity in ("CRITICAL", "HIGH") and bool(recommended_version),
            "recommended_version": recommended_version,
            "risk_level": "MEDIUM",
            "strategy": "fallback-rule-based",
            "justification": f"Fallback: {str(e)}"
        }


def analisar_lote(vulnerabilidades):
    """
    Analisa um lote de vulnerabilidades e retorna decisões individuais.

    vulnerabilidades: lista de dicts com campos do banco vulnerability_records
    Retorna: lista de dicts com decisão por vuln
    """
    resultados = []

    # Agrupa por pacote para chamar IA uma vez por pacote
    pacotes_vistos = {}
    for vuln in vulnerabilidades:
        pkg = vuln["package_name"]
        if pkg not in pacotes_vistos:
            pacotes_vistos[pkg] = vuln

    for pkg, vuln in pacotes_vistos.items():
        print(f"  🧠 IA analisando {pkg} {vuln['installed_version']} ({vuln['severity']})...")

        decisao = analisar_vulnerabilidade(
            package_name=vuln["package_name"],
            installed_version=vuln["installed_version"],
            severity=vuln["severity"],
            cve_id=vuln["cve_id"],
            fixed_versions=vuln.get("fixed_version", ""),
            ecosystem=vuln.get("ecosystem", "PHP"),
            recommended_version=vuln.get("recommended_version")
        )

        print(f"    → {'✅ APPROVED' if decisao['approved'] else '❌ NOT APPROVED'}: {decisao['justification'][:80]}...")

        resultados.append({
            "package_name": pkg,
            "decision": "APPROVED" if decisao["approved"] else "MANUAL_REVIEW",
            "recommended_version": decisao.get("recommended_version"),
            "justification": decisao.get("justification", ""),
            "strategy": decisao.get("strategy", ""),
            "risk_level": decisao.get("risk_level", "")
        })

    return resultados

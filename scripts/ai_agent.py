"""
Agente de IA - Cérebro do Framework de Remediação SCA

Requisitos:
  Req 3  - Análise orientada por IA via Google Gemini
  Req 4  - IA como tomadora de decisão
  Req 10 - Retry com backoff exponencial

IMPORTANTE:
- Trivy fornece evidências de segurança.
- OSV fornece recomendações de versão.
- Supabase armazena essas evidências.
- homologated_versions fornece versões homologadas.
- A IA analisa essas informações e toma a decisão.
- Se a IA estiver indisponível, o framework NÃO tenta gerar
  Virtual Patch. O fallback utiliza a versão recomendada
  armazenada no banco, validada contra o FixedVersion do Trivy.
"""

import os
import re
import json
import time

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()


MODEL = os.getenv("AI_MODEL", "gemini-2.5-flash")
MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "600"))
TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.1"))
MAX_RETRIES = 5


# ============================================================
# CLIENTE IA
# ============================================================

def get_client():
    """
    Cria o cliente Gemini.

    Se GEMINI_API_KEY não estiver disponível, lança exceção.
    O framework.py captura essa falha e utiliza o fallback do banco.
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY não configurada."
        )

    genai.configure(api_key=api_key)

    model = genai.GenerativeModel(
        MODEL,
        generation_config=genai.GenerationConfig(
            max_output_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
    )

    return model


# ============================================================
# RETRY
# ============================================================

def _call_with_retry(model, prompt):
    """
    Retry com backoff exponencial.

    Após todas as tentativas, propaga a exceção para que
    o framework utilize o fallback do banco.
    """

    for attempt in range(MAX_RETRIES):

        try:
            response = model.generate_content(prompt)

            return response.text or ""

        except Exception as e:

            if attempt == MAX_RETRIES - 1:
                raise

            delay = 2 ** attempt

            print(
                f"    ⚠️ Tentativa {attempt + 1} falhou: {e}. "
                f"Retry em {delay}s..."
            )

            time.sleep(delay)


# ============================================================
# BANCO CURADO
# ============================================================

def get_curated_versions(package_name, ecosystem):
    """
    Consulta as versões homologadas no Supabase.

    Essas versões servem como evidência adicional para a IA
    e como fallback secundário.

    IMPORTANTE:
    A homologação não substitui a evidência do Trivy/OSV.
    """

    try:

        from db import connect_db

        conn = connect_db()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                safe_version,
                approved_by,
                notes,
                approved_at
            FROM homologated_versions
            WHERE package_name = %s
              AND ecosystem = %s
            ORDER BY approved_at DESC
            """,
            (package_name, ecosystem)
        )

        rows = cur.fetchall()

        cur.close()
        conn.close()

        return [
            {
                "version": row[0],
                "approved_by": row[1],
                "notes": row[2],
                "approved_at": str(row[3])
                if row[3]
                else None,
            }
            for row in rows
        ]

    except Exception as e:

        print(
            f"    ⚠️ Erro ao consultar homologated_versions: {e}"
        )

        return []


# ============================================================
# VERSÕES
# ============================================================

def _normalize_versions(value):
    """
    Normaliza versões provenientes do Trivy/OSV.

    Exemplos:

        "7.15.2"
        "7.15.2, 8.0.1"
        ["7.15.2", "8.0.1"]
    """

    if not value:
        return []

    if isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = [value]

    versions = []

    for item in values:

        if not item:
            continue

        if isinstance(item, str):

            parts = re.split(
                r"\s*,\s*|\s*;\s*",
                item
            )

            versions.extend(
                part.strip()
                for part in parts
                if part.strip()
            )

        else:

            versions.append(str(item))

    return list(dict.fromkeys(versions))


def _version_key(version):
    """
    Compara versões de forma simples.
    """

    try:

        from packaging.version import Version

        return Version(
            str(version).lstrip("v")
        )

    except Exception:

        nums = re.findall(
            r"\d+",
            str(version)
        )

        return tuple(
            int(n)
            for n in nums
        ) or (0,)


def _max_version(versions):
    """
    Retorna a maior versão da lista.
    """

    versions = _normalize_versions(versions)

    if not versions:
        return None

    return max(
        versions,
        key=_version_key
    )


def _version_meets_trivy_requirement(
    candidate,
    fixed_versions
):
    """
    Verifica se uma versão atende aos requisitos de segurança
    fornecidos pelo Trivy.

    Para múltiplas CVEs, considera o maior FixedVersion informado.
    """

    if not candidate:
        return False

    fixed_versions = _normalize_versions(
        fixed_versions
    )

    if not fixed_versions:
        return False

    required = _max_version(
        fixed_versions
    )

    if not required:
        return False

    return (
        _version_key(candidate)
        >= _version_key(required)
    )


# ============================================================
# CANDIDATO HOMOLOGADO
# ============================================================

def _select_curated_version(
    curated_versions,
    fixed_versions,
    installed_version
):
    """
    Seleciona uma versão homologada segura.

    Estratégia:

    1. Procura versão homologada que atenda ao Trivy
       dentro do mesmo major.
    2. Caso não exista, aceita major superior.
    """

    candidates = [
        item["version"]
        for item in curated_versions
        if item.get("version")
        and _version_meets_trivy_requirement(
            item["version"],
            fixed_versions
        )
    ]

    if not candidates:
        return None

    installed_major = (
        str(installed_version or "")
        .lstrip("v")
        .split(".")[0]
    )

    same_major = [
        version
        for version in candidates
        if (
            str(version)
            .lstrip("v")
            .split(".")[0]
            == installed_major
        )
    ]

    if same_major:

        return min(
            same_major,
            key=_version_key
        )

    return min(
        candidates,
        key=_version_key
    )


# ============================================================
# ANÁLISE DE UM PACOTE
# ============================================================

def analisar_pacote(
    package_name,
    installed_version,
    severity,
    cves,
    fixed_versions,
    ecosystem,
    recommended_version=None
):
    """
    A IA analisa todas as evidências e toma a decisão.

    Evidências:

      - versão instalada
      - CVEs
      - FixedVersion do Trivy
      - recomendação do OSV armazenada no banco
      - versões homologadas

    A IA retorna uma única versão para o pacote.
    """

    client = get_client()

    curated_versions = get_curated_versions(
        package_name,
        ecosystem
    )

    fixed_versions = _normalize_versions(
        fixed_versions
    )

    minimum_required_version = _max_version(
        fixed_versions
    )

    curated_candidate = _select_curated_version(
        curated_versions,
        fixed_versions,
        installed_version
    )

    # ========================================================
    # CONTEXTO ENVIADO PARA A IA
    # ========================================================

    context = {
        "package": package_name,
        "ecosystem": ecosystem,
        "installed_version": installed_version,

        "severity": severity,

        "cves": cves,

        # Evidência Trivy
        "trivy_fixed_versions": fixed_versions,
        "trivy_minimum_required_version":
            minimum_required_version,

        # Evidência OSV armazenada no banco
        "osv_recommended_version":
            recommended_version,

        # Banco curado
        "homologated_versions": [
            item["version"]
            for item in curated_versions
        ],

        "homologated_safe_candidate":
            curated_candidate,

        "compatibility_policy":
            "Prefer same-major when security requirements are satisfied; "
            "otherwise a newer major may be selected."
    }

    # ========================================================
    # PROMPT
    # ========================================================

    prompt = f"""
You are an autonomous DevSecOps security agent.

You are the FINAL DECISION MAKER.

The following systems provide evidence:

- Trivy: vulnerability detection and FixedVersion.
- OSV: vulnerability remediation recommendation.
- Supabase: persistent database containing the OSV recommendation.
- Homologated database: versions previously approved by the security team.

Your task is to analyze ALL CVEs affecting the package and choose
ONE remediation version.

Evidence:

{json.dumps(context, indent=2)}

Decision rules:

1. The selected version MUST address all CVEs affecting the package.

2. Never select a version lower than the minimum version required
   by Trivy.

3. Consider the OSV recommended version stored in the database
   as an important remediation recommendation.

4. If the OSV/database recommendation satisfies the Trivy
   security requirement, it is a valid candidate.

5. If a homologated version satisfies the Trivy requirement,
   prefer it when it provides equivalent security.

6. Same-major is a compatibility preference, NOT a security rule.

7. If no safe same-major version exists, a newer major can be used.

8. CRITICAL and HIGH vulnerabilities should normally be remediated
   automatically when a safe version is available.

9. MEDIUM vulnerabilities may be automatically remediated when
   sufficient evidence exists.

10. LOW vulnerabilities may be ignored when remediation risk
    outweighs the security benefit.

11. If evidence is insufficient, return MANUAL_REVIEW.

12. Do NOT invent a version.

13. Do NOT use Virtual Patch.

14. Return exactly ONE remediation version.

Return ONLY valid JSON:

{{
    "approved": true,
    "recommended_version": "VERSION",
    "risk_level": "LOW|MEDIUM|HIGH",
    "strategy": "same-major|newer-major|manual-review",
    "justification": "Brief explanation based on Trivy, OSV and database evidence."
}}
"""

    try:

        content = _call_with_retry(
            client,
            prompt
        ).strip()

        # Remove markdown fences
        if content.startswith("```"):

            lines = content.split("\n")

            if (
                len(lines) > 2
                and lines[-1].strip() == "```"
            ):

                content = "\n".join(
                    lines[1:-1]
                )

            else:

                content = "\n".join(
                    lines[1:]
                )

        content = content.strip()

        # ====================================================
        # JSON
        # ====================================================

        try:

            result = json.loads(content)

        except json.JSONDecodeError:

            match = re.search(
                r'\{.*?"approved"\s*:\s*'
                r'(true|false).*?\}',
                content,
                re.DOTALL
            )

            if not match:
                raise

            result = json.loads(
                match.group(0)
            )

        selected = result.get(
            "recommended_version"
        )

        # ====================================================
        # GUARDRAIL TRIVY
        # ====================================================

        if result.get("approved"):

            if not selected:

                result["approved"] = False
                result["strategy"] = "manual-review"
                result["justification"] = (
                    "IA aprovou a remediação, "
                    "mas não informou uma versão."
                )

            elif not _version_meets_trivy_requirement(
                selected,
                fixed_versions
            ):

                result["approved"] = False
                result["strategy"] = "manual-review"
                result["justification"] = (
                    f"A versão {selected} não atende "
                    f"ao requisito mínimo do Trivy "
                    f"({minimum_required_version})."
                )

        return result

    except Exception as e:

        print(
            f"    ⚠️ IA indisponível durante análise: {e}"
        )

        # ====================================================
        # IMPORTANTE:
        # FALLBACK NÃO É OUTRA IA.
        #
        # Usa a recomendação já armazenada no banco,
        # originada do OSV.
        # ====================================================

        database_candidate = None

        if recommended_version:

            if _version_meets_trivy_requirement(
                recommended_version,
                fixed_versions
            ):

                database_candidate = (
                    recommended_version
                )

        # Se a recomendação do OSV não estiver disponível
        # ou não atender ao Trivy, usa o banco homologado.

        if not database_candidate:

            database_candidate = (
                curated_candidate
            )

        if database_candidate:

            installed_major = (
                str(installed_version or "")
                .lstrip("v")
                .split(".")[0]
            )

            candidate_major = (
                str(database_candidate)
                .lstrip("v")
                .split(".")[0]
            )

            strategy = (
                "same-major"
                if installed_major == candidate_major
                else "newer-major"
            )

            return {
                "approved": severity in (
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM"
                ),

                "recommended_version":
                    database_candidate,

                "risk_level":
                    "MEDIUM"
                    if severity == "MEDIUM"
                    else "HIGH",

                "strategy":
                    strategy,

                "justification": (
                    "Fallback automático: IA indisponível. "
                    f"Utilizada a versão {database_candidate} "
                    "armazenada no banco como recomendação "
                    "do OSV, validada contra o requisito "
                    f"do Trivy ({minimum_required_version})."
                )
            }

        # ====================================================
        # SEM VERSÃO SEGURA
        # ====================================================

        return {
            "approved": False,
            "recommended_version": None,
            "risk_level": "HIGH",
            "strategy": "manual-review",
            "justification": (
                "IA indisponível e o banco não possui uma "
                "versão segura capaz de atender ao requisito "
                f"do Trivy ({minimum_required_version or 'não informado'})."
            )
        }


# ============================================================
# ANÁLISE EM LOTE
# ============================================================

def analisar_lote(vulnerabilidades):
    """
    Consolida vulnerabilidades por pacote e envia uma decisão
    única para cada pacote.
    """

    pacotes = {}

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    for vuln in vulnerabilidades:

        pkg = vuln["package_name"]

        if pkg not in pacotes:

            pacotes[pkg] = {
                "package_name": pkg,
                "installed_version":
                    vuln["installed_version"],
                "severity":
                    vuln["severity"],
                "cves": [],
                "fixed_versions": [],
                "ecosystem":
                    vuln.get(
                        "ecosystem",
                        "PHP"
                    ),
                "recommended_versions": [],
                "ids": [],
            }

        info = pacotes[pkg]

        info["cves"].append(
            vuln["cve_id"]
        )

        info["ids"].append(
            vuln["id"]
        )

        info["fixed_versions"].extend(
            _normalize_versions(
                vuln.get("fixed_version")
            )
        )

        if vuln.get("recommended_version"):

            info["recommended_versions"].append(
                vuln["recommended_version"]
            )

        current_rank = severity_order.get(
            info["severity"],
            9
        )

        new_rank = severity_order.get(
            vuln["severity"],
            9
        )

        if new_rank < current_rank:

            info["severity"] = (
                vuln["severity"]
            )

    resultados = []

    for pkg, info in pacotes.items():

        fixed_versions = list(
            dict.fromkeys(
                info["fixed_versions"]
            )
        )

        # ====================================================
        # IMPORTANTE:
        # A recomendação do banco/OSV é preservada.
        #
        # Se houver várias, a primeira registrada é utilizada
        # como evidência para a IA.
        # ====================================================

        recommended_version = (
            info["recommended_versions"][0]
            if info["recommended_versions"]
            else None
        )

        print(
            f"  🧠 IA analisando {pkg} "
            f"{info['installed_version']} "
            f"(severity: {info['severity']}, "
            f"CVEs: {len(info['cves'])})..."
        )

        print(
            "      Trivy FixedVersions: "
            f"{', '.join(fixed_versions) "
            if fixed_versions else 'nenhuma'}"
        )

        print(
            "      OSV/Supabase recommendation: "
            f"{recommended_version or 'N/A'}"
        )

        decisao = analisar_pacote(
            package_name=pkg,
            installed_version=
                info["installed_version"],
            severity=info["severity"],
            cves=info["cves"],
            fixed_versions=fixed_versions,
            ecosystem=info["ecosystem"],
            recommended_version=
                recommended_version
        )

        status = (
            "✅ APPROVED"
            if decisao.get("approved")
            else "⏸️ MANUAL_REVIEW"
        )

        print(
            f"    → {status}: "
            f"{decisao.get('recommended_version')} — "
            f"{decisao.get('justification', '')[:150]}"
        )

        resultados.append({
            "package_name": pkg,
            "ids": info["ids"],

            "decision":
                "APPROVED"
                if decisao.get("approved")
                else "MANUAL_REVIEW",

            "recommended_version":
                decisao.get(
                    "recommended_version"
                ),

            "justification":
                decisao.get(
                    "justification",
                    ""
                ),

            "strategy":
                decisao.get(
                    "strategy",
                    ""
                ),

            "risk_level":
                decisao.get(
                    "risk_level",
                    "MEDIUM"
                ),
        })

    return resultados

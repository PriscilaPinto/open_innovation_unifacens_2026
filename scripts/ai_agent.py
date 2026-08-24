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
- Se a IA estiver indisponível, o framework utiliza o fallback
  baseado nas evidências armazenadas no banco.
- Virtual Patch não é utilizado neste agente.
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
    O framework.py poderá utilizar o fallback do banco.
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

    Até 5 tentativas.

    Após todas as tentativas, propaga a exceção para que
    o framework utilize o fallback.
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
    Consulta as versões homologadas no banco.

    Essas versões são evidências adicionais para a IA
    e também podem ser utilizadas no fallback.
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
            (
                package_name,
                ecosystem
            )
        )

        rows = cur.fetchall()

        cur.close()
        conn.close()

        return [
            {
                "version": row[0],
                "approved_by": row[1],
                "notes": row[2],
                "approved_at": (
                    str(row[3])
                    if row[3]
                    else None
                ),
            }
            for row in rows
        ]

    except Exception as e:

        print(
            f"    ⚠️ Erro ao consultar "
            f"homologated_versions: {e}"
        )

        return []


# ============================================================
# NORMALIZAÇÃO DE VERSÕES
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

    if isinstance(
        value,
        (list, tuple, set)
    ):
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

            versions.append(
                str(item)
            )

    return list(
        dict.fromkeys(versions)
    )


# ============================================================
# COMPARAÇÃO DE VERSÕES
# ============================================================

def _version_key(version):
    """
    Compara versões utilizando packaging.version.

    Possui fallback para versões que não possam ser
    interpretadas pelo parser semântico.
    """

    try:

        from packaging.version import Version

        return Version(
            str(version)
            .lstrip("v")
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

    versions = _normalize_versions(
        versions
    )

    if not versions:
        return None

    return max(
        versions,
        key=_version_key
    )


# ============================================================
# VALIDAÇÃO CONTRA TRIVY
# ============================================================

def _version_meets_trivy_requirement(
    candidate,
    fixed_versions
):
    """
    Verifica se uma versão atende ao requisito de segurança
    fornecido pelo Trivy.

    Quando existem múltiplas CVEs, utiliza a maior
    FixedVersion como requisito consolidado.
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
# SELEÇÃO DE VERSÃO HOMOLOGADA
# ============================================================

def _select_curated_version(
    curated_versions,
    fixed_versions,
    installed_version
):
    """
    Seleciona uma versão homologada que atende
    ao requisito de segurança do Trivy.

    Estratégia:

    1. Procura uma versão homologada que atenda
       ao Trivy no mesmo major da versão instalada.

    2. Se não existir, procura uma versão homologada
       de major superior que atenda ao Trivy.

    IMPORTANTE:
    Same-major é somente uma preferência de compatibilidade.
    Não é uma restrição de segurança.
    """

    candidates = [
        item["version"]
        for item in curated_versions
        if (
            item.get("version")
            and _version_meets_trivy_requirement(
                item["version"],
                fixed_versions
            )
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
    recommended_versions=None
):
    """
    A IA analisa todas as evidências e toma a decisão.

    Evidências utilizadas:

      - versão instalada
      - CVEs
      - FixedVersion do Trivy
      - recomendações do OSV armazenadas no banco
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

    recommended_versions = _normalize_versions(
        recommended_versions
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

        # ----------------------------------------------------
        # Evidências do Trivy
        # ----------------------------------------------------

        "trivy_fixed_versions": fixed_versions,

        "trivy_minimum_required_version":
            minimum_required_version,

        # ----------------------------------------------------
        # Evidências do OSV armazenadas no banco
        # ----------------------------------------------------

        "osv_recommended_versions":
            recommended_versions,

        # ----------------------------------------------------
        # Banco homologado
        # ----------------------------------------------------

        "homologated_versions": [
            item["version"]
            for item in curated_versions
        ],

        "homologated_safe_candidate":
            curated_candidate,

        # ----------------------------------------------------
        # Política de compatibilidade
        # ----------------------------------------------------

        "compatibility_policy":
            (
                "Prefer same-major when security requirements "
                "are satisfied; otherwise a newer major may "
                "be selected."
            )
    }

    # ========================================================
    # PROMPT DA IA
    # ========================================================

    prompt = f"""
You are an autonomous DevSecOps security agent.

You are the FINAL DECISION MAKER.

The following systems provide evidence:

- Trivy: vulnerability detection and FixedVersion.
- OSV: vulnerability remediation recommendations.
- Supabase: persistent database containing OSV evidence.
- Homologated database: versions previously approved by
  the security team.

Your task is to analyze ALL CVEs affecting the package
and choose ONE remediation version.

Evidence:

{json.dumps(context, indent=2)}

Decision rules:

1. The selected version MUST address ALL CVEs affecting
   the package.

2. Never select a version lower than the minimum version
   required by Trivy.

3. Consider ALL OSV recommended versions stored in the
   database as remediation evidence.

4. If an OSV recommended version satisfies the Trivy
   security requirement, it is a valid candidate.

5. If a homologated version satisfies the Trivy
   requirement, prefer it when it provides equivalent
   security.

6. Same-major is a compatibility preference,
   NOT a security restriction.

7. If no safe same-major version exists, a newer major
   can be selected.

8. CRITICAL and HIGH vulnerabilities should normally
   be remediated automatically when a safe version exists.

9. MEDIUM vulnerabilities may be automatically remediated
   when sufficient evidence exists.

10. LOW vulnerabilities may be ignored when remediation
    risk outweighs the security benefit.

11. If evidence is insufficient, return MANUAL_REVIEW.

12. Do NOT invent a version.

13. Do NOT select a version lower than the Trivy requirement.

14. Do NOT use Virtual Patch.

15. Return exactly ONE remediation version.

16. The final decision must consider Trivy, OSV and the
    homologated database together.

Return ONLY valid JSON:

{{
    "approved": true,
    "recommended_version": "VERSION",
    "risk_level": "LOW|MEDIUM|HIGH",
    "strategy": "same-major|newer-major|manual-review",
    "justification": "Brief explanation based on Trivy, OSV and database evidence."
}}
"""

    # ========================================================
    # EXECUÇÃO DA IA
    # ========================================================

    try:

        content = _call_with_retry(
            client,
            prompt
        ).strip()

        # ----------------------------------------------------
        # Remove markdown fences
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # Parse JSON
        # ----------------------------------------------------

        try:

            result = json.loads(
                content
            )

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

        # ====================================================
        # GUARDRAIL DE SEGURANÇA
        # ====================================================

        selected = result.get(
            "recommended_version"
        )

        if result.get("approved"):

            # ------------------------------------------------
            # IA aprovou sem indicar versão
            # ------------------------------------------------

            if not selected:

                result["approved"] = False

                result["strategy"] = (
                    "manual-review"
                )

                result["justification"] = (
                    "IA aprovou a remediação, "
                    "mas não informou uma versão."
                )

            # ------------------------------------------------
            # IA escolheu versão abaixo do Trivy
            # ------------------------------------------------

            elif not _version_meets_trivy_requirement(
                selected,
                fixed_versions
            ):

                result["approved"] = False

                result["strategy"] = (
                    "manual-review"
                )

                result["justification"] = (
                    f"A versão {selected} não atende "
                    f"ao requisito mínimo do Trivy "
                    f"({minimum_required_version})."
                )

        return result

    # ========================================================
    # FALLBACK
    # ========================================================

    except Exception as e:

        print(
            f"    ⚠️ IA indisponível durante análise: {e}"
        )

        """
        FALLBACK:

        A IA não conseguiu tomar a decisão.

        Nesse cenário, o framework utiliza as evidências
        persistidas no banco.

        Ordem:

        1. Recomendação do OSV armazenada no banco,
           desde que atenda ao Trivy.

        2. Caso contrário, versão homologada que
           atenda ao Trivy.

        Nunca utilizar uma versão abaixo do requisito
        de segurança do Trivy.
        """

        database_candidate = None

        # ----------------------------------------------------
        # Primeiro: OSV/Supabase
        # ----------------------------------------------------

        for candidate in recommended_versions:

            if _version_meets_trivy_requirement(
                candidate,
                fixed_versions
            ):

                database_candidate = candidate

                break

        # ----------------------------------------------------
        # Segundo: banco homologado
        # ----------------------------------------------------

        if not database_candidate:

            database_candidate = (
                curated_candidate
            )

        # ----------------------------------------------------
        # Existe versão segura
        # ----------------------------------------------------

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
                    (
                        "MEDIUM"
                        if severity == "MEDIUM"
                        else "HIGH"
                    ),

                "strategy":
                    strategy,

                "justification":
                    (
                        "Fallback automático: IA indisponível. "
                        f"Utilizada a versão {database_candidate} "
                        "encontrada nas evidências persistidas "
                        "no banco e validada contra o requisito "
                        f"do Trivy ({minimum_required_version})."
                    )
            }

        # ----------------------------------------------------
        # Nenhuma versão segura encontrada
        # ----------------------------------------------------

        return {
            "approved": False,

            "recommended_version": None,

            "risk_level": "HIGH",

            "strategy": "manual-review",

            "justification":
                (
                    "IA indisponível e o banco não possui "
                    "uma versão segura capaz de atender "
                    "ao requisito do Trivy "
                    f"({minimum_required_version or 'não informado'})."
                )
        }


# ============================================================
# ANÁLISE EM LOTE
# ============================================================

def analisar_lote(vulnerabilidades):
    """
    Consolida vulnerabilidades por pacote e envia
    uma única decisão para cada pacote.

    Todas as CVEs do mesmo pacote são analisadas
    conjuntamente.
    """

    pacotes = {}

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    # ========================================================
    # AGRUPAMENTO
    # ========================================================

    for vuln in vulnerabilidades:

        pkg = vuln["package_name"]

        if pkg not in pacotes:

            pacotes[pkg] = {

                "package_name":
                    pkg,

                "installed_version":
                    vuln["installed_version"],

                "severity":
                    vuln["severity"],

                "cves":
                    [],

                "fixed_versions":
                    [],

                "ecosystem":
                    vuln.get(
                        "ecosystem",
                        "PHP"
                    ),

                "recommended_versions":
                    [],

                "ids":
                    [],
            }

        info = pacotes[pkg]

        # ----------------------------------------------------
        # CVE
        # ----------------------------------------------------

        info["cves"].append(
            vuln["cve_id"]
        )

        # ----------------------------------------------------
        # ID da vulnerabilidade
        # ----------------------------------------------------

        info["ids"].append(
            vuln["id"]
        )

        # ----------------------------------------------------
        # FixedVersion do Trivy
        # ----------------------------------------------------

        info["fixed_versions"].extend(
            _normalize_versions(
                vuln.get("fixed_version")
            )
        )

        # ----------------------------------------------------
        # Recomendação OSV
        # ----------------------------------------------------

        if vuln.get(
            "recommended_version"
        ):

            info[
                "recommended_versions"
            ].append(
                vuln["recommended_version"]
            )

        # ----------------------------------------------------
        # Maior severidade
        # ----------------------------------------------------

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

    # ========================================================
    # DECISÃO POR PACOTE
    # ========================================================

    resultados = []

    for pkg, info in pacotes.items():

        # ----------------------------------------------------
        # Remove duplicidades
        # ----------------------------------------------------

        fixed_versions = list(
            dict.fromkeys(
                info["fixed_versions"]
            )
        )

        recommended_versions = list(
            dict.fromkeys(
                info["recommended_versions"]
            )
        )

        # ----------------------------------------------------
        # Log
        # ----------------------------------------------------

        print(
            f"  🧠 IA analisando {pkg} "
            f"{info['installed_version']} "
            f"(severity: {info['severity']}, "
            f"CVEs: {len(info['cves'])})..."
        )

        # ====================================================
        # CORREÇÃO DO ERRO DE SINTAXE
        # ====================================================

        print(
            "      Trivy FixedVersions: "
            f"{', '.join(fixed_versions) if fixed_versions else 'nenhuma'}"
        )

        print(
            "      OSV/Supabase recommendations: "
            f"{', '.join(recommended_versions) if recommended_versions else 'N/A'}"
        )

        # ----------------------------------------------------
        # Análise IA
        # ----------------------------------------------------

        decisao = analisar_pacote(

            package_name=
                pkg,

            installed_version=
                info["installed_version"],

            severity=
                info["severity"],

            cves=
                info["cves"],

            fixed_versions=
                fixed_versions,

            ecosystem=
                info["ecosystem"],

            recommended_versions=
                recommended_versions
        )

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # Resultado
        # ----------------------------------------------------

        resultados.append({

            "package_name":
                pkg,

            "ids":
                info["ids"],

            "decision":
                (
                    "APPROVED"
                    if decisao.get("approved")
                    else "MANUAL_REVIEW"
                ),

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

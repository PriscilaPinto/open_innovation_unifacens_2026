"""
Agente de IA - Cérebro do Framework de Remediação
Requisito 3: Análise orientada por IA via Google Gemini (gratuito)
Requisito 10: Retry com backoff exponencial até 5 tentativas
Requisito 4: A IA é a TOMADORA DE DECISÃO. Trivy, OSV e o banco curado
             fornecem EVIDÊNCIAS; same-major é uma preferência de
             compatibilidade, não uma restrição de segurança imposta
             antes da IA decidir.

NOTA: Usa Google Generative AI direto (sem OpenRouter).
      Chave gratuita em: https://aistudio.google.com/apikey
      Modelo: gemini-2.5-flash (gratuito, 60 req/min)
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


def get_client():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY não configurada.\n"
            "Obtenha sua chave gratuita em: https://aistudio.google.com/apikey"
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


def _call_with_retry(model, prompt):
    """Req 10: retry com backoff exponencial até 5 tentativas."""
    for attempt in range(MAX_RETRIES):
        try:
            response = model.generate_content(prompt)
            return response.text or ""
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


def _normalize_versions(value):
    """Converte FixedVersion/versões do OSV em uma lista de versões individuais."""
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
            # Trivy pode entregar "7.15.2, 8.0.1"
            parts = re.split(r"\s*,\s*|\s*;\s*", item)
            versions.extend(p.strip() for p in parts if p.strip())
        else:
            versions.append(str(item))

    # Remove duplicatas preservando ordem
    return list(dict.fromkeys(versions))


def _version_key(version):
    """Chave simples para comparação semântica de versões."""
    try:
        from packaging.version import Version
        return Version(str(version).lstrip("v"))
    except Exception:
        nums = re.findall(r"\d+", str(version))
        return tuple(int(n) for n in nums)


def _max_version(versions):
    versions = _normalize_versions(versions)
    if not versions:
        return None
    return max(versions, key=_version_key)


def _select_curated_version(curated_versions, fixed_versions, installed_version):
    """
    Seleciona a menor versão homologada que seja >= à maior versão
    de correção informada pelo Trivy para o conjunto de CVEs.

    A preferência same-major é aplicada somente quando existe uma
    versão homologada segura dentro do mesmo major. Caso contrário,
    permite major superior.
    """
    curated = [
        v["version"] for v in curated_versions
        if v.get("version")
    ]
    fixed = _normalize_versions(fixed_versions)

    if not curated:
        return None

    required = _max_version(fixed)
    if not required:
        # Sem FixedVersion consolidada, não inventa uma versão.
        return None

    installed_major = str(installed_version).lstrip("v").split(".")[0]

    # Primeiro tenta homologada same-major e >= ao maior requisito.
    same_major = [
        v for v in curated
        if str(v).lstrip("v").split(".")[0] == installed_major
        and _version_key(v) >= _version_key(required)
    ]
    if same_major:
        return min(same_major, key=_version_key)

    # Se não existe same-major suficiente, permite major superior.
    newer = [v for v in curated if _version_key(v) >= _version_key(required)]
    if newer:
        return min(newer, key=_version_key)

    return None


def analisar_pacote(package_name, installed_version, severity, cves,
                     fixed_versions, ecosystem, recommended_version=None):
    """
    Req 3: IA consulta evidências de Trivy/OSV e decide a remediação.
    Req 4: banco curado fornece versões homologadas.
    Req 3.5: múltiplas CVEs do mesmo pacote são consolidadas.
    """
    client = get_client()

    curated_versions = get_curated_versions(package_name, ecosystem)
    fixed_versions = _normalize_versions(fixed_versions)

    # Determina a maior versão necessária para corrigir TODAS as CVEs.
    minimum_required_version = _max_version(fixed_versions)

    # O banco curado é uma fonte de evidência/homologação, não apenas
    # uma lista decorativa. Já calculamos a menor homologada que atende
    # ao conjunto de correções informado pelo Trivy.
    curated_candidate = _select_curated_version(
        curated_versions,
        fixed_versions,
        installed_version
    )

    context = {
        "package": package_name,
        "ecosystem": ecosystem,
        "installed_version": installed_version,
        "highest_severity": severity,
        "cves_affected": cves,
        "fixed_versions_available": fixed_versions,
        "minimum_version_required_by_trivy": minimum_required_version,
        "recommended_version_from_osv": recommended_version,
        "curated_approved_versions": [v["version"] for v in curated_versions],
        "curated_candidate_meeting_trivy_requirements": curated_candidate,
        "project_type": "legacy - minimize breaking changes; same-major preferred"
    }

    prompt = f"""You are an autonomous DevSecOps security agent.

You are the FINAL DECISION MAKER. Trivy, OSV and the curated database
provide technical evidence; they do not make the decision for you.

Analyze ALL CVEs of this package together and choose ONE remediation version.

Context:
{json.dumps(context, indent=2)}

Mandatory security rules:
1. The selected version MUST fix ALL CVEs listed in cves_affected.
2. Use Trivy fixed_versions_available as the primary evidence for the
   minimum security requirement.
3. Do NOT choose an OSV version merely because it fixes one CVE if another
   CVE requires a newer version.
4. If a curated_candidate_meeting_trivy_requirements exists, strongly
   prefer it because it is homologated by the security team.
5. same-major is a COMPATIBILITY PREFERENCE, NOT a security restriction.
6. If no safe same-major homologated version exists, a newer major may be
   selected when it is the first safe/homologated option.
7. CRITICAL/HIGH with a safe homologated version should normally be APPROVED.
8. MEDIUM may be APPROVED when the selected version is safe and homologated.
9. LOW may be IGNORE when remediation risk outweighs the security benefit.
10. If the evidence is insufficient to select a safe version, use MANUAL_REVIEW.
11. Consolidate all CVEs of this package into ONE version update.

For this decision, do not select a version lower than
minimum_version_required_by_trivy.

Respond ONLY with valid JSON:
{{"approved": true, "recommended_version": "VERSION", "risk_level": "LOW|MEDIUM|HIGH", "strategy": "same-major|newer-major|virtual-patch|manual-review", "justification": "Brief explanation using Trivy, OSV and curated evidence."}}"""

    try:
        content = _call_with_retry(client, prompt).strip()

        if content.startswith("```"):
            lines = content.split("\n")
            if len(lines) > 2 and lines[-1].strip() == "```":
                content = "\n".join(lines[1:-1])
            else:
                content = "\n".join(lines[1:])

        content = content.strip()

        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(
                r'\{.*?"approved"\s*:\s*(true|false).*?\}',
                content,
                re.DOTALL
            )
            if not match:
                raise
            raw = match.group(0).replace("\n", " ").replace("\r", " ")
            raw = raw.replace('\\"', "'")
            result = json.loads(raw)

        # Guardrail: a IA não pode aprovar uma versão inferior ao
        # requisito consolidado do Trivy.
        selected = result.get("recommended_version")
        if result.get("approved") and minimum_required_version and selected:
            if _version_key(selected) < _version_key(minimum_required_version):
                result["approved"] = False
                result["strategy"] = "manual-review"
                result["justification"] = (
                    f"IA selecionou {selected}, mas o Trivy exige pelo menos "
                    f"{minimum_required_version} para cobrir todas as CVEs. "
                    "Decisão rebaixada para MANUAL_REVIEW."
                )

        return result

    except Exception as e:
        print(f"    ⚠️ Erro na análise da IA: {e}")

        # Fallback seguro: usa APENAS uma versão homologada que atende
        # ao requisito consolidado do Trivy. Nunca cai para OSV isoladamente
        # quando isso poderia resultar em uma versão vulnerável.
        safe_ver = curated_candidate

        if safe_ver:
            return {
                "approved": severity in ("CRITICAL", "HIGH", "MEDIUM"),
                "recommended_version": safe_ver,
                "risk_level": "MEDIUM" if severity == "MEDIUM" else "HIGH",
                "strategy": (
                    "same-major" if str(safe_ver).split(".")[0] ==
                    str(installed_version).split(".")[0]
                    else "newer-major"
                ),
                "justification": (
                    f"Fallback seguro: {safe_ver} é versão homologada e "
                    f"atende ao requisito consolidado do Trivy "
                    f"({minimum_required_version})."
                )
            }

        return {
            "approved": False,
            "recommended_version": None,
            "risk_level": "HIGH",
            "strategy": "manual-review",
            "justification": (
                f"Não foi possível determinar uma versão homologada que "
                f"atenda a todas as CVEs. Requisito mínimo do Trivy: "
                f"{minimum_required_version or 'não informado'}."
            )
        }

def gerar_virtual_patch(package_name, cves, installed_version, ecosystem):
    """
    Gera um virtual patch para mitigar vulnerabilidades SEM alterar a versão da lib.
    Usado quando o update da dependência quebra compatibilidade (smoke test falha).
    
    Args:
        package_name: Nome do pacote vulnerável (ex: guzzlehttp/guzzle)
        cves: Lista de CVEs a mitigar
        installed_version: Versão atual instalada
        ecosystem: PHP, Node.js ou Python
    
    Retorna:
        dict com patch_code, file_path e justification ou None se falhar
    """
    try:
        model = get_client()
    except Exception as e:
        print(f"    ⚠️  Erro ao criar cliente IA para virtual patch: {e}")
        return None

    # Define o tipo de arquivo e sintaxe baseado no ecossistema
    if ecosystem == "PHP":
        file_ext = "php"
        language = "PHP"
        comment = "//"
        filename_safe = package_name.replace("/", "_").replace("-", "_")
    elif ecosystem == "Node.js":
        file_ext = "js"
        language = "JavaScript"
        comment = "//"
        filename_safe = package_name.replace("/", "_").replace("-", "_")
    else:
        file_ext = "py"
        language = "Python"
        comment = "#"
        filename_safe = package_name.replace("/", "_").replace("-", "_")

    prompt = f"""You are a DevSecOps security engineer. A legacy project has a vulnerable dependency that CANNOT be updated because the new version breaks compatibility.

Generate a VIRTUAL PATCH — a code file that will be loaded by the application to MITIGATE the vulnerabilities WITHOUT changing the dependency version.

Package: {package_name} (version {installed_version})
Ecosystem: {ecosystem}
Language: {language}
CVEs to mitigate: {', '.join(cves)}

The virtual patch MUST:
1. Be valid {language} code that can be included/required by the main application
2. Intercept or wrap the vulnerable functionality to block the CVE attack vectors
3. NOT modify the original library files
4. Include clear comments explaining each mitigation
5. Start with a header comment identifying it as an auto-generated virtual patch

Return ONLY the source code, no markdown fences, no explanation.
""" + f"""
Example structure for PHP (adapt for {language}):
{comment} ============================================
{comment} Virtual Patch - Auto-generated by AI Agent
{comment} Package: {package_name}
{comment} CVEs: {', '.join(cves)}
{comment} This patch mitigates vulnerabilities without updating the library.
{comment} Generated: {__import__('datetime').datetime.now().isoformat()}
{comment} ============================================

[actual mitigation code here]
"""

    try:
        content = _call_with_retry(model, prompt)
        if not content:
            return None
            
        # Remove markdown fences se presentes
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1]) if len(lines) > 2 and lines[-1].strip() == "```" else "\n".join(lines[1:])
        content = content.strip()
        
        # Caminho do arquivo
        patch_dir = "virtual_patches"
        os.makedirs(patch_dir, exist_ok=True)
        file_path = f"{patch_dir}/{filename_safe}_virtual_patch.{file_ext}"
        
        # Salva o patch
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        print(f"      ✅ Virtual patch gerado: {file_path} ({len(content)} bytes)")
        
        return {
            "patch_code": content,
            "file_path": file_path,
            "justification": f"Virtual Patch gerado para {package_name} ({', '.join(cves)}). "
                           f"Update quebrou compatibilidade, mitigação aplicada em {file_path}"
        }
    except Exception as e:
        print(f"    ⚠️  Erro ao gerar virtual patch: {e}")
        return None


def analisar_lote(vulnerabilidades):
    """
    Req 3: Analisa um lote agrupado por pacote.
    Req 3.5: Consolida múltiplas CVEs do mesmo pacote em uma única decisão.
    """
    pacotes = {}

    for vuln in vulnerabilidades:
        pkg = vuln["package_name"]

        if pkg not in pacotes:
            pacotes[pkg] = {
                "package_name": pkg,
                "installed_version": vuln["installed_version"],
                "severity": vuln["severity"],
                "cves": [],
                "fixed_versions": [],
                "ecosystem": vuln.get("ecosystem", "PHP"),
                "recommended_versions": [],
                "ids": []
            }

        info = pacotes[pkg]

        info["cves"].append(vuln["cve_id"])
        info["ids"].append(vuln["id"])

        # IMPORTANTÍSSIMO:
        # Não guarda somente o FixedVersion da primeira CVE.
        # Todas as correções precisam ser consolidadas.
        info["fixed_versions"].extend(
            _normalize_versions(vuln.get("fixed_version"))
        )

        if vuln.get("recommended_version"):
            info["recommended_versions"].append(
                vuln["recommended_version"]
            )

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        if sev_order.get(vuln["severity"], 9) < sev_order.get(info["severity"], 9):
            info["severity"] = vuln["severity"]

    resultados = []

    for pkg, info in pacotes.items():
        fixed_versions = list(dict.fromkeys(info["fixed_versions"]))
        recommended_version = (
            info["recommended_versions"][0]
            if info["recommended_versions"]
            else None
        )

        print(
            f"  🧠 IA analisando {pkg} {info['installed_version']} "
            f"(severity: {info['severity']}, CVEs: {len(info['cves'])})..."
        )
        print(
            f"      Trivy FixedVersions consolidadas: "
            f"{', '.join(fixed_versions) if fixed_versions else 'nenhuma'}"
        )

        decisao = analisar_pacote(
            package_name=pkg,
            installed_version=info["installed_version"],
            severity=info["severity"],
            cves=info["cves"],
            fixed_versions=fixed_versions,
            ecosystem=info["ecosystem"],
            recommended_version=recommended_version
        )

        status = (
            "✅ APPROVED"
            if decisao.get("approved")
            else "⏸️  MANUAL_REVIEW"
        )

        print(
            f"    → {status}: "
            f"{decisao.get('recommended_version')} — "
            f"{decisao.get('justification', '')[:120]}"
        )

        resultados.append({
            "package_name": pkg,
            "ids": info["ids"],
            "decision": "APPROVED" if decisao.get("approved") else "MANUAL_REVIEW",
            "recommended_version": decisao.get("recommended_version"),
            "justification": decisao.get("justification", ""),
            "strategy": decisao.get("strategy", ""),
            "risk_level": decisao.get("risk_level", "MEDIUM")
        })

    return resultados


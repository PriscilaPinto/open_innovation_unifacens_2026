"""
STAGE 1 - Persistencia de Historico + Consulta OSV
Le vulnerabilidades do relatorio Trivy, consulta banco curado (Supabase),
fallback para OSV API (Google), e salva no Supabase com rastreabilidade completa.

Requisito 3: Analise com consulta a OSV
Requisito 12: Historico persistente com source_db
"""
import json
import re
import requests
import time
from dotenv import load_dotenv
from db import connect_db

load_dotenv()

OSV_API_ENDPOINT = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 10
OSV_RETRIES = 3


def query_curated_db(cur, package_name, ecosystem, installed_version=None):
    """
    Consulta banco de dados curado (homologated_versions).
    Prioridade: banco curado > OSV API (Req 3.3)

    Estrategia de selecao:
      1. Busca TODAS as versoes homologadas do pacote/ecossistema.
      2. Prefere a versao same-major mais baixa em relacao a instalada
         (menor impacto de compatibilidade, alinhado ao NIST SP 800-40).
      3. Se nao existir same-major, retorna a versao homologada mais baixa
         disponivel (menos disruptiva entre as opcoes cross-major).

    Retorna dict com safe_version, recommended_version, source, approved_by, notes, osv_id
    ou None se nao encontrar.
    """

    def _ver_key(v):
        nums = re.findall(r"\d+", str(v or ""))
        return tuple(int(n) for n in nums) if nums else (0,)

    try:
        cur.execute("""
            SELECT safe_version, approved_by, notes
            FROM homologated_versions
            WHERE package_name = %s AND ecosystem = %s
            ORDER BY approved_at DESC
        """, (package_name, ecosystem))

        rows = cur.fetchall()

        if not rows:
            return None

        # Determina major da versao instalada para preferencia same-major.
        installed_major = None
        if installed_version:
            installed_major = (
                str(installed_version).lstrip("v").split(".")[0]
            )

        same_major = []
        all_versions = list(rows)

        for row in rows:
            candidate_major = str(row[0]).lstrip("v").split(".")[0]
            if installed_major and candidate_major == installed_major:
                same_major.append(row)

        # Usa same-major se disponivel; caso contrario, pool completo.
        pool = same_major if same_major else all_versions
        # Retorna a versao mais baixa do pool (menor impacto).
        best = min(pool, key=lambda r: _ver_key(r[0]))

        return {
            "safe_version": best[0],
            "recommended_version": best[0],
            "source": "CURATED_DB",
            "approved_by": best[1],
            "notes": best[2],
            "osv_id": None
        }

    except Exception as e:
        print(f"    Erro ao consultar banco curado: {e}")

    return None


def query_osv_api(package_name, installed_version, ecosystem):
    """
    Consulta OSV API (https://osv.dev).
    Fallback quando banco curado nao tem dados (Req 3.4).

    Ecossistemas suportados: PHP -> Packagist, Node.js -> npm, Python -> PyPI.
    Retorna dict com osv_id, safe_version, recommended_version, source, fixed_versions ou None.
    """
    osv_ecosystem_map = {
        "PHP": "Packagist",
        "Node.js": "npm",
        "Python": "PyPI"
    }

    osv_eco = osv_ecosystem_map.get(ecosystem, ecosystem)

    payload = {
        "package": {"ecosystem": osv_eco, "name": package_name},
        "version": installed_version
    }

    for attempt in range(OSV_RETRIES):
        try:
            response = requests.post(
                OSV_API_ENDPOINT,
                json=payload,
                timeout=OSV_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulns", [])
            if not vulns:
                return None

            all_fixed = set()
            for vuln in vulns:
                for affected in vuln.get("affected", []):
                    for range_item in affected.get("ranges", []):
                        for event in range_item.get("events", []):
                            if "fixed" in event:
                                all_fixed.add(event["fixed"])

            fixed_sorted = sorted(
                list(all_fixed),
                key=lambda v: [
                    int(x) if x.isdigit() else 0
                    for x in v.split(".")
                ]
            )

            safe_version = fixed_sorted[0] if fixed_sorted else None

            if safe_version:
                return {
                    "osv_id": vulns[0].get("id", "UNKNOWN"),
                    "safe_version": safe_version,
                    "recommended_version": safe_version,
                    "source": "OSV_API",
                    "fixed_versions": fixed_sorted,
                    "severity": vulns[0].get("severity", "UNKNOWN"),
                    "all_fixed_versions": list(all_fixed)
                }

            return None

        except requests.exceptions.Timeout:
            print(f"    OSV API timeout (tentativa {attempt + 1}/{OSV_RETRIES})")
        except requests.exceptions.RequestException as e:
            print(f"    OSV API erro: {e} (tentativa {attempt + 1}/{OSV_RETRIES})")
        except Exception as e:
            print(f"    Erro ao processar OSV: {e}")

        if attempt < OSV_RETRIES - 1:
            time.sleep(2 ** attempt)

    return None


def query_vulnerability_data(cur, package_name, installed_version, ecosystem):
    """
    Consulta dados de vulnerabilidade. Prioridade: banco curado > OSV API.

    Req 3.3: Banco curado tem prioridade (versao recomendada)
    Req 3.4: OSV API consultada MESMO quando curado existir, para osv_id
    Req 12:  Salva osv_reference e source_db no banco

    Fluxo:
      1. Banco curado com selecao same-major (installed_version).
      2. Enriquece com OSV para obter osv_id.
      3. Fallback OSV se curado nao encontrou.
      4. None se nenhum disponivel.
    """
    curated = query_curated_db(cur, package_name, ecosystem, installed_version)

    if curated:
        print(f"      [CURATED_DB] {package_name} -> {curated.get('recommended_version')}")
        print(f"      [Enriquecendo com OSV API] {package_name} {installed_version}")
        osv_data = query_osv_api(package_name, installed_version, ecosystem)

        if osv_data:
            curated["osv_id"] = osv_data.get("osv_id")
            curated["all_fixed_versions"] = osv_data.get("all_fixed_versions", [])
            curated["fixed_versions"] = osv_data.get("fixed_versions", [])
            curated["source"] = "CURATED_DB"
            print(f"      OSV enriquecido: {curated.get('osv_id')}")
        else:
            print(f"      OSV nao retornou dados extras (apenas curado)")

        return curated

    print(f"      [Consultando OSV API] {package_name} {installed_version}")
    osv_data = query_osv_api(package_name, installed_version, ecosystem)
    if osv_data:
        print(f"      [OSV_API] {package_name} -> {osv_data.get('recommended_version')} ({osv_data.get('osv_id')})")
        return osv_data

    print(f"      Nenhuma versao recomendada encontrada para {package_name}")
    return None


def persist_vulnerability_record(cur, conn, execution_id, vuln_data, vdata, ecosystem):
    """
    Insere registro de vulnerabilidade no Supabase.
    Req 5: Sem duplicacao. Multi-linguagem: salva ecosystem rastreado.
    """
    cve_id = vuln_data.get("VulnerabilityID")
    pkg = vuln_data.get("PkgName")
    version = vuln_data.get("InstalledVersion")
    severity = vuln_data.get("Severity", "UNKNOWN")
    fixed_ver = vuln_data.get("FixedVersion")

    if not vdata:
        try:
            cur.execute("""
                INSERT INTO vulnerability_records
                    (execution_id, cve_id, package_name, severity,
                     installed_version, fixed_version, remediation_status,
                     osv_reference, recommended_version, source_db, ecosystem)
                VALUES (%s, %s, %s, %s, %s, %s, 'OPEN', %s, %s, %s, %s)
            """, (
                execution_id, cve_id, pkg, severity, version, fixed_ver,
                None, None, "NONE", ecosystem
            ))
            conn.commit()
        except Exception as e:
            print(f"        DB error: {e}")
            conn.rollback()
        return

    osv_ref = vdata.get("osv_id")
    rec_ver = vdata.get("recommended_version")
    source = vdata.get("source", "UNKNOWN")

    try:
        cur.execute("""
            INSERT INTO vulnerability_records
                (execution_id, cve_id, package_name, severity,
                 installed_version, fixed_version, remediation_status,
                 osv_reference, recommended_version, source_db, ecosystem)
            VALUES (%s, %s, %s, %s, %s, %s, 'OPEN', %s, %s, %s, %s)
        """, (
            execution_id, cve_id, pkg, severity, version, fixed_ver,
            osv_ref, rec_ver, source, ecosystem
        ))
        conn.commit()
    except Exception as e:
        print(f"        DB error: {e}")
        conn.rollback()


def main(execution_id, report_path="reports/report.json"):
    """
    STAGE 1: Le relatorio Trivy, consulta OSV/curado, persiste no Supabase.
    Multi-linguagem verdadeiro -- detecta ecossistema de CADA vulnerabilidade.

    Req 3: Consulta OSV | Req 12: Historico persistente | Req 5: Sem duplicacao
    """
    print("\n" + "=" * 60)
    print("STAGE 1 -- Persistencia + Consulta OSV/Curado (Multi-Linguagem)")
    print("=" * 60)

    try:
        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)
    except FileNotFoundError:
        print(f"Relatorio nao encontrado: {report_path}")
        return 0
    except json.JSONDecodeError as e:
        print(f"Erro ao ler JSON: {e}")
        return 0

    conn = connect_db()
    cur = conn.cursor()

    results = report.get("Results", [])
    total_vulns = sum(len(r.get("Vulnerabilities") or []) for r in results)

    if total_vulns == 0:
        print("Nenhuma vulnerabilidade detectada")
        cur.close()
        conn.close()
        return 0

    print(f"Vulnerabilidades detectadas: {total_vulns}")

    count = 0
    for result in results:
        result_ecosystem = result.get("Type", "").lower()

        if "composer" in result_ecosystem:
            ecosystem = "PHP"
        elif "npm" in result_ecosystem or "package" in result_ecosystem.lower():
            ecosystem = "Node.js"
        elif "pip" in result_ecosystem or "poetry" in result_ecosystem:
            ecosystem = "Python"
        else:
            ecosystem = "UNKNOWN"

        print(f"\nEcossistema: {ecosystem} (Type: {result.get('Type')})")

        for vuln in (result.get("Vulnerabilities") or []):
            count += 1
            pkg = vuln.get("PkgName")
            version = vuln.get("InstalledVersion")
            sev = vuln.get("Severity", "UNKNOWN")
            print(f"  [{count}] {pkg}:{version} [{sev}]")
            vdata = query_vulnerability_data(cur, pkg, version, ecosystem)
            persist_vulnerability_record(
                cur, conn, execution_id, vuln, vdata, ecosystem
            )

    cur.close()
    conn.close()

    print(f"\n{count} registros persistidos no Supabase (multi-linguagem)")
    return count


if __name__ == "__main__":
    import uuid
    main(str(uuid.uuid4()))

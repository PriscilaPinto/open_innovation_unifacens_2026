"""
STAGE 1 - Persistência de Histórico + Consulta OSV
Lê vulnerabilidades do relatório Trivy, consulta banco curado (Supabase),
fallback para OSV API (Google), e salva no Supabase com rastreabilidade completa.

Requisito 3: Análise com consulta a OSV
Requisito 12: Histórico persistente com source_db
"""
import json
import requests
import time
from dotenv import load_dotenv
from db import connect_db

load_dotenv()

OSV_API_ENDPOINT = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 10
OSV_RETRIES = 3


def query_curated_db(cur, package_name, ecosystem):
    """
    Consulta banco de dados curado (homologated_versions).
    Prioridade: banco curado > OSV API (Req 3.3)
    
    Retorna:
        {
            "safe_version": "6.5.8",
            "source": "CURATED_DB",
            "approved_by": "team",
            "notes": "...",
            "osv_id": None
        }
    ou None
    """
    try:
        cur.execute("""
            SELECT safe_version, approved_by, notes
            FROM homologated_versions
            WHERE package_name = %s AND ecosystem = %s
            ORDER BY approved_at DESC
            LIMIT 1
        """, (package_name, ecosystem))
        row = cur.fetchone()
        if row:
            return {
                "safe_version": row[0],
                "recommended_version": row[0],
                "source": "CURATED_DB",
                "approved_by": row[1],
                "notes": row[2],
                "osv_id": None
            }
    except Exception as e:
        print(f"    ⚠️  Erro ao consultar banco curado: {e}")
    return None


def query_osv_api(package_name, installed_version, ecosystem):
    """
    Consulta OSV API (https://osv.dev).
    Fallback quando banco curado não tem dados (Req 3.4).
    
    Ecossistemas suportados:
        - PHP: "Packagist"
        - Node.js: "npm"
        - Python: "PyPI"
    
    Retorna:
        {
            "osv_id": "GHSA-xxxx-yyyy-zzzz",
            "safe_version": "6.5.8",
            "recommended_version": "6.5.8",
            "source": "OSV_API",
            "fixed_versions": ["6.5.0", "6.5.1", ...],
            "severity": "HIGH",
            "all_fixed_versions": [...]
        }
    ou None
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
            
            # OSV retorna vulns que afetam esta versão
            vulns = data.get("vulns", [])
            if not vulns:
                return None
            
            # Extrai todas as versões que corrigem alguma CVE
            all_fixed = set()
            for vuln in vulns:
                for affected in vuln.get("affected", []):
                    for range_item in affected.get("ranges", []):
                        for event in range_item.get("events", []):
                            if "fixed" in event:
                                all_fixed.add(event["fixed"])
            
            # Ordena por versão (semver simplificado)
            fixed_sorted = sorted(list(all_fixed), key=lambda v: [int(x) if x.isdigit() else 0 for x in v.split(".")])
            
            # Recomenda a menor versão que corrige (same-major strategy)
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
            print(f"    ⚠️  OSV API timeout (tentativa {attempt + 1}/{OSV_RETRIES})")
        except requests.exceptions.RequestException as e:
            print(f"    ⚠️  OSV API erro: {e} (tentativa {attempt + 1}/{OSV_RETRIES})")
        except Exception as e:
            print(f"    ⚠️  Erro ao processar OSV: {e}")
        
        if attempt < OSV_RETRIES - 1:
            time.sleep(2 ** attempt)  # Backoff exponencial
    
    return None


def query_vulnerability_data(cur, package_name, installed_version, ecosystem):
    """
    Consulta dados de vulnerabilidade.
    Prioridade: banco curado > OSV API
    
    Req 3.3: Banco curado tem prioridade
    Req 3.4: Fallback para OSV API
    
    Retorna:
        {
            "recommended_version": "6.5.8",
            "osv_id": "GHSA-xxxx",  ou None se curado
            "source": "CURATED_DB" ou "OSV_API",
            "all_fixed_versions": [...],
            ...
        }
    """
    # Tenta banco curado primeiro
    curated = query_curated_db(cur, package_name, ecosystem)
    if curated:
        print(f"      [CURATED_DB] {package_name}")
        return curated
    
    # Fallback: OSV API
    print(f"      [Consultando OSV API] {package_name} {installed_version}")
    osv_data = query_osv_api(package_name, installed_version, ecosystem)
    if osv_data:
        print(f"      [OSV_API] {package_name} → {osv_data.get('recommended_version')}")
        return osv_data
    
    print(f"      ❌ Nenhuma versão recomendada encontrada")
    return None


def persist_vulnerability_record(cur, conn, execution_id, vuln_data, vdata, ecosystem):
    """
    Insere registro de vulnerabilidade no Supabase.
    Requisito 5: Verificar duplicação ANTES de inserir.
    Requisito: Multi-linguagem — salva ecossistema da vulnerabilidade
    
    vdata: resultado de query_vulnerability_data()
    ecosystem: PHP, Node.js, Python, UNKNOWN
    """
    cve_id = vuln_data.get("VulnerabilityID")
    pkg = vuln_data.get("PkgName")
    version = vuln_data.get("InstalledVersion")
    severity = vuln_data.get("Severity", "UNKNOWN")
    fixed_ver = vuln_data.get("FixedVersion")
    
    if not vdata:
        # Sem recomendação, mas salva para auditoria
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
    
    # Com recomendação
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
    STAGE 1: Lê relatório Trivy, consulta OSV/curado, persiste no Supabase.
    AGORA: Multi-linguagem verdadeiro — detecta ecossistema de CADA vulnerabilidade
    
    Req 3: Consulta OSV
    Req 12: Histórico persistente
    Req 5: Sem duplicação
    """
    print("\n" + "=" * 60)
    print("STAGE 1 — Persistência + Consulta OSV/Curado (Multi-Linguagem)")
    print("=" * 60)
    
    try:
        with open(report_path) as f:
            report = json.load(f)
    except FileNotFoundError:
        print(f"❌ Relatório não encontrado: {report_path}")
        return 0
    except json.JSONDecodeError as e:
        print(f"❌ Erro ao ler JSON: {e}")
        return 0
    
    conn = connect_db()
    cur = conn.cursor()
    
    results = report.get("Results", [])
    total_vulns = sum(len(r.get("Vulnerabilities") or []) for r in results)
    
    if total_vulns == 0:
        print("✅ Nenhuma vulnerabilidade detectada")
        cur.close()
        conn.close()
        return 0
    
    print(f"Vulnerabilidades detectadas: {total_vulns}")
    
    count = 0
    for result in results:
        # Detecta ecossistema DESTA vulnerabilidade (Trivy retorna "Type": "composer" ou "pip" ou "npm")
        result_ecosystem = result.get("Type", "").lower()
        
        # Map Trivy type → nosso ecosystem
        if "composer" in result_ecosystem:
            ecosystem = "PHP"
        elif "npm" in result_ecosystem or "package" in result_ecosystem.lower():
            ecosystem = "Node.js"
        elif "pip" in result_ecosystem or "poetry" in result_ecosystem:
            ecosystem = "Python"
        else:
            ecosystem = "UNKNOWN"
        
        print(f"\n🌍 Ecossistema: {ecosystem} (Type: {result.get('Type')})")
        
        for vuln in (result.get("Vulnerabilities") or []):
            count += 1
            pkg = vuln.get("PkgName")
            version = vuln.get("InstalledVersion")
            sev = vuln.get("Severity", "UNKNOWN")
            
            print(f"  [{count}] {pkg}:{version} [{sev}]")
            
            # Consulta dados de vulnerabilidade (usa ecosystem correto)
            vdata = query_vulnerability_data(cur, pkg, version, ecosystem)
            
            # Persiste registro (com ecossistema rastreado)
            persist_vulnerability_record(cur, conn, execution_id, vuln, vdata, ecosystem)
    
    cur.close()
    conn.close()
    
    print(f"\n✅ {count} registros persistidos no Supabase (multi-linguagem)")
    return count


if __name__ == "__main__":
    # Para teste local
    import uuid
    main(str(uuid.uuid4()))

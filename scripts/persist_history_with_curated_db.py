"""
Versão alternativa do persist_history.py que:
1. PRIMEIRO consulta banco de versões homologadas (curadas pela equipe)
2. Se não encontrar, consulta OSV API como fallback
"""
import json
import requests
import os
from dotenv import load_dotenv

from db import connect_db

load_dotenv()


def query_homologated_version(cursor, package_name, ecosystem='PHP'):
    """
    Consulta versão homologada no banco local (curada pela equipe)
    """
    cursor.execute("""
        SELECT safe_version, approved_by, notes
        FROM homologated_versions
        WHERE package_name = %s
        AND ecosystem = %s
        ORDER BY approved_at DESC
        LIMIT 1
    """, (package_name, ecosystem))
    
    result = cursor.fetchone()
    
    if result:
        return {
            "source": "CURATED_DB",
            "recommended_version": result[0],
            "approved_by": result[1],
            "notes": result[2]
        }
    
    return None


def query_osv(package_name, version):
    """
    Consulta OSV API como fallback
    """
    url = "https://api.osv.dev/v1/query"

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "Packagist"
        },
        "version": version
    }

    try:
        response = requests.post(url, json=payload)

        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])

            if vulns:
                vuln = vulns[0]
                osv_id = vuln.get("id")
                recommended_version = None

                affected = vuln.get("affected", [])

                if affected:
                    ranges = affected[0].get("ranges", [])

                    if ranges:
                        events = ranges[0].get("events", [])

                        for event in events:
                            if "fixed" in event:
                                recommended_version = event["fixed"]

                return {
                    "source": "OSV_API",
                    "osv_id": osv_id,
                    "recommended_version": recommended_version
                }

        return None

    except Exception as e:
        print(f'OSV query error: {e}')
        return None


try:
    conn = connect_db()

    cursor = conn.cursor()

    # Salvar execução do pipeline
    cursor.execute("""
        INSERT INTO pipeline_executions (
            repository_name, workflow_run_id, status,
            vulnerabilities_found, vulnerabilities_resolved,
            reduction_percentage
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        'open_innovation_virtual',
        os.getenv('GITHUB_RUN_ID', 'local-run'),
        'SUCCESS',
        0, 0, 0
    ))

    execution_id = cursor.fetchone()[0]

    # Carregar relatório Trivy
    with open('reports/report.json', 'r') as file:
        report = json.load(file)

    vulnerabilities_found = 0

    for result in report.get('Results', []):
        vulnerabilities = result.get('Vulnerabilities', [])

        for vuln in vulnerabilities:
            vulnerabilities_found += 1
            
            package_name = vuln.get('PkgName')
            installed_version = vuln.get('InstalledVersion')

            # ==========================================
            # ESTRATÉGIA HÍBRIDA:
            # 1. Tenta banco curado primeiro
            # 2. Fallback para OSV API
            # ==========================================
            
            print(f"🔍 Buscando versão para {package_name}...")
            
            # Tenta banco curado
            version_data = query_homologated_version(cursor, package_name)
            
            if version_data:
                print(f"  ✅ Encontrado no banco curado (aprovado por: {version_data['approved_by']})")
            else:
                print(f"  ⚠️  Não encontrado no banco curado, consultando OSV API...")
                version_data = query_osv(package_name, installed_version)
                
                if version_data:
                    print(f"  ✅ Encontrado na OSV API")
                else:
                    print(f"  ❌ Não encontrado em nenhuma fonte")

            # Inserir vulnerabilidade
            cursor.execute("""
                INSERT INTO vulnerability_records (
                    execution_id, cve_id, package_name,
                    severity, installed_version, fixed_version,
                    remediation_status, osv_reference, recommended_version
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                execution_id,
                vuln.get('VulnerabilityID'),
                package_name,
                vuln.get('Severity'),
                installed_version,
                vuln.get('FixedVersion'),
                'OPEN',
                version_data.get('osv_id') if version_data else None,
                version_data.get('recommended_version') if version_data else None
            ))

    # Atualizar métricas
    cursor.execute("""
        UPDATE pipeline_executions
        SET vulnerabilities_found = %s
        WHERE id = %s
    """, (vulnerabilities_found, execution_id))

    conn.commit()

    print(f'\n✅ Execution saved: {execution_id}')
    print(f'✅ Vulnerabilities saved: {vulnerabilities_found}')

    cursor.close()
    conn.close()

except Exception as e:
    print(f'❌ Error: {e}')

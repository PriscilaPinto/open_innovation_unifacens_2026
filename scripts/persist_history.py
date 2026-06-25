import json
import psycopg2
import requests


# ==========================================
# OSV QUERY FUNCTION
# ==========================================

def query_osv(package_name, version):

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
                    "osv_id": osv_id,
                    "recommended_version": recommended_version
                }

        return None

    except Exception as e:

        print(f'OSV query error: {e}')

        return None


# ==========================================
# MAIN EXECUTION
# ==========================================

try:

    conn = psycopg2.connect(
        host='localhost',
        port=5432,
        database='remediation',
        user='postgres',
        password='postgres'
    )

    cursor = conn.cursor()

    # ==========================================
    # SAVE PIPELINE EXECUTION
    # ==========================================

    cursor.execute(
        '''
        INSERT INTO pipeline_executions (

            repository_name,
            workflow_run_id,
            status,
            vulnerabilities_found,
            vulnerabilities_resolved,
            reduction_percentage

        )

        VALUES (%s, %s, %s, %s, %s, %s)

        RETURNING id
        ''',
        (
            'open_innovation_virtual',
            'run-001',
            'SUCCESS',
            0,
            0,
            0
        )
    )

    execution_id = cursor.fetchone()[0]

    # ==========================================
    # LOAD TRIVY REPORT
    # ==========================================

    with open('reports/report.json', 'r') as file:
        report = json.load(file)

    vulnerabilities_found = 0

    # ==========================================
    # SAVE VULNERABILITIES
    # ==========================================

    for result in report.get('Results', []):

        vulnerabilities = result.get('Vulnerabilities', [])

        for vuln in vulnerabilities:

            vulnerabilities_found += 1

            # ==========================================
            # QUERY OSV API
            # ==========================================

            osv_data = query_osv(
                vuln.get('PkgName'),
                vuln.get('InstalledVersion')
            )

            # ==========================================
            # INSERT VULNERABILITY
            # ==========================================

            cursor.execute(
                '''
                INSERT INTO vulnerability_records (

                    execution_id,
                    cve_id,
                    package_name,
                    severity,
                    installed_version,
                    fixed_version,
                    remediation_status,
                    osv_reference,
                    recommended_version

                )

                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''',
                (
                    execution_id,
                    vuln.get('VulnerabilityID'),
                    vuln.get('PkgName'),
                    vuln.get('Severity'),
                    vuln.get('InstalledVersion'),
                    vuln.get('FixedVersion'),
                    'OPEN',
                    osv_data['osv_id'] if osv_data else None,
                    osv_data['recommended_version'] if osv_data else None
                )
            )

    # ==========================================
    # UPDATE EXECUTION METRICS
    # ==========================================

    cursor.execute(
        '''
        UPDATE pipeline_executions
        SET vulnerabilities_found = %s
        WHERE id = %s
        ''',
        (
            vulnerabilities_found,
            execution_id
        )
    )

    conn.commit()

    print(f'Execution saved: {execution_id}')
    print(f'Vulnerabilities saved: {vulnerabilities_found}')

    cursor.close()
    conn.close()

except Exception as e:

    print(f'Error: {e}')
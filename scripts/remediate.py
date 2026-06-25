import psycopg2
import subprocess
import shutil


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
    # CHECK COMPOSER PATH
    # ==========================================

    composer_path = shutil.which("composer")

    if composer_path is None:
        raise Exception("Composer não encontrado no PATH do sistema")

    # ==========================================
    # GET APPROVED REMEDIATIONS
    # ==========================================

    cursor.execute(
        '''
        SELECT
            id,
            package_name,
            recommended_version
        FROM vulnerability_records
        WHERE decision_status = 'APPROVED'
        AND remediation_status = 'OPEN'
        '''
    )

    vulnerabilities = cursor.fetchall()

    remediated = 0
    failed = 0

    # ==========================================
    # REMEDIATION LOOP
    # ==========================================

    for vuln in vulnerabilities:

        vulnerability_id = vuln[0]
        package_name = vuln[1]
        recommended_version = vuln[2]

        print(f'Remediating {package_name} -> {recommended_version}')

        # ==========================================
        # COMPOSER REQUIRE (FIXED)
        # ==========================================

        command = [
            composer_path,
            'require',
            f'{package_name}:{recommended_version}'
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True
        )

        # ==========================================
        # SUCCESS
        # ==========================================

        if result.returncode == 0:

            print('Remediation successful')

            cursor.execute(
                '''
                UPDATE vulnerability_records
                SET remediation_status = 'REMEDIATED'
                WHERE id = %s
                ''',
                (vulnerability_id,)
            )

            remediated += 1

        # ==========================================
        # FAILED
        # ==========================================

        else:

            print('Remediation failed')
            print(result.stderr)

            cursor.execute(
                '''
                UPDATE vulnerability_records
                SET remediation_status = 'FAILED'
                WHERE id = %s
                ''',
                (vulnerability_id,)
            )

            failed += 1

    conn.commit()

    print(f'Remediated: {remediated}')
    print(f'Failed: {failed}')

    cursor.close()
    conn.close()

except Exception as e:

    print(f'Error: {e}')
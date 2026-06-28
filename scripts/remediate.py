import psycopg2
import subprocess
import shutil
import os
from dotenv import load_dotenv

load_dotenv()

try:
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 5432)),
        database=os.getenv("DB_NAME", "remediation"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres")
    )

    cursor = conn.cursor()

    composer_path = shutil.which("composer")

    if composer_path is None:
        raise Exception("Composer não encontrado no PATH do sistema")

    cursor.execute("""
        SELECT id, package_name, recommended_version
        FROM vulnerability_records
        WHERE decision_status = 'APPROVED'
        AND remediation_status = 'OPEN'
    """)

    vulnerabilities = cursor.fetchall()

    remediated = 0
    failed = 0

    for vuln in vulnerabilities:

        vulnerability_id, package_name, recommended_version = vuln

        print(f"Remediating {package_name} -> {recommended_version}")

        command = [
            composer_path,
            "require",
            f"{package_name}:{recommended_version}"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:

            print("Remediation successful")

            cursor.execute("""
                UPDATE vulnerability_records
                SET remediation_status = 'REMEDIATED'
                WHERE id = %s
            """, (vulnerability_id,))

            remediated += 1

        else:

            print("Remediation failed")
            print(result.stderr)

            cursor.execute("""
                UPDATE vulnerability_records
                SET remediation_status = 'FAILED'
                WHERE id = %s
            """, (vulnerability_id,))

            failed += 1

    conn.commit()

    print(f"Remediated: {remediated}")
    print(f"Failed: {failed}")

    cursor.close()
    conn.close()

except Exception as e:
    print(f"Error: {e}")
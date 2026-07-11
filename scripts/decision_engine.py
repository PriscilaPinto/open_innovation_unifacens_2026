"""
STAGE 2 - Engine de Decisão
Analisa vulnerabilidades OPEN e decide: APPROVED / MANUAL_REVIEW / IGNORE.
Agrupa por pacote para evitar remediação duplicada do mesmo pacote.
"""
from dotenv import load_dotenv
from db import connect_db

load_dotenv()

SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}


def main():
    conn = connect_db()
    cursor = conn.cursor()

    # Busca um representante por pacote (pior severidade) entre os OPEN sem decisão
    cursor.execute("""
        SELECT DISTINCT ON (package_name)
            id, package_name, severity, recommended_version
        FROM vulnerability_records
        WHERE remediation_status = 'OPEN'
          AND decision_status = 'PENDING'
        ORDER BY package_name,
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                ELSE 5
            END
    """)
    packages = cursor.fetchall()

    approved = manual = ignored = 0

    for row in packages:
        _, pkg, severity, recommended_version = row

        if severity in ("CRITICAL", "HIGH") and recommended_version:
            decision = "APPROVED"
            approved += 1
        elif severity == "LOW":
            decision = "IGNORE"
            ignored += 1
        else:
            decision = "MANUAL_REVIEW"
            manual += 1

        # Aplica a decisão a TODAS as CVEs do mesmo pacote
        cursor.execute("""
            UPDATE vulnerability_records
            SET decision_status = %s
            WHERE package_name = %s
              AND remediation_status = 'OPEN'
              AND decision_status = 'PENDING'
        """, (decision, pkg))

        print(f"  {pkg}: {decision} (severity: {severity})")

    conn.commit()
    print(f"\nApproved: {approved} | Manual Review: {manual} | Ignored: {ignored}")
    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()

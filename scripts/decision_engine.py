from dotenv import load_dotenv

from db import connect_db

# Carrega variáveis de ambiente
load_dotenv()


try:

    conn = connect_db()

    cursor = conn.cursor()

    # ==========================================
    # GET OPEN VULNERABILITIES
    # ==========================================

    # Agrupa por pacote para evitar remediação duplicada
    cursor.execute(
        '''
        SELECT DISTINCT ON (package_name)
            id,
            severity,
            recommended_version,
            package_name

        FROM vulnerability_records

        WHERE remediation_status = 'OPEN'

        ORDER BY package_name, 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                ELSE 4
            END
        '''
    )

    vulnerabilities = cursor.fetchall()

    approved = 0
    manual_review = 0
    ignored = 0

    # ==========================================
    # DECISION ENGINE
    # ==========================================

    for vuln in vulnerabilities:

        vulnerability_id = vuln[0]
        severity = vuln[1]
        recommended_version = vuln[2]
        package_name = vuln[3]

        decision = 'MANUAL_REVIEW'

        # ==========================================
        # APPROVED REMEDIATION
        # ==========================================

        if severity in ['HIGH', 'CRITICAL'] and recommended_version:

            decision = 'APPROVED'

            approved += 1

        # ==========================================
        # IGNORE LOW
        # ==========================================

        elif severity == 'LOW':

            decision = 'IGNORE'

            ignored += 1

        else:

            manual_review += 1

        # Atualiza todas as CVEs do mesmo pacote com a mesma decisão
        cursor.execute(
            '''
            UPDATE vulnerability_records
            SET decision_status = %s
            WHERE package_name = %s
            AND remediation_status = 'OPEN'
            ''',
            (decision, package_name)
        )

        print(f'Vulnerability decision: {decision}')

    conn.commit()

    print(f'Approved: {approved}')
    print(f'Manual Review: {manual_review}')
    print(f'Ignored: {ignored}')

    cursor.close()
    conn.close()

except Exception as e:

    print(f'Error: {e}')

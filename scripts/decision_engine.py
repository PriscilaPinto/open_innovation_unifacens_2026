import psycopg2


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
    # GET OPEN VULNERABILITIES
    # ==========================================

    cursor.execute(
        '''
        SELECT
            id,
            severity,
            recommended_version

        FROM vulnerability_records

        WHERE remediation_status = 'OPEN'
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

        # ==========================================
        # UPDATE DECISION
        # ==========================================

        cursor.execute(
            '''
            UPDATE vulnerability_records

            SET decision_status = %s

            WHERE id = %s
            ''',
            (
                decision,
                vulnerability_id
            )
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
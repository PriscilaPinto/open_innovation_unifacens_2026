import subprocess
import shutil
import os
from dotenv import load_dotenv

from context_collector import detect_ecosystem
from db import connect_db

# Carrega variáveis de ambiente
load_dotenv()


# ==========================================
# DETECT ECOSYSTEM
# ==========================================

context = detect_ecosystem()

package_manager = context.get("package_manager")

print(f'Ecosystem detected: {context.get("ecosystem")}')
print(f'Package manager detected: {package_manager}')


# ==========================================
# PACKAGE MANAGER COMMANDS
# ==========================================

manager_commands = {

    "composer": {
        "binary": "composer",
        "command_builder": lambda pkg, ver: [
            "composer",
            "require",
            f"{pkg}:{ver}"
        ]
    },

    "npm": {
        "binary": "npm",
        "command_builder": lambda pkg, ver: [
            "npm",
            "install",
            f"{pkg}@{ver}"
        ]
    },

    "pip": {
        "binary": "pip",
        "command_builder": lambda pkg, ver: [
            "pip",
            "install",
            f"{pkg}=={ver}"
        ]
    }
}


try:

    # ==========================================
    # VALIDATE PACKAGE MANAGER
    # ==========================================

    if package_manager not in manager_commands:

        raise Exception(
            f'Supported package manager not found: {package_manager}'
        )

    binary_name = manager_commands[package_manager]["binary"]

    binary_path = shutil.which(binary_name)

    if binary_path is None:

        raise Exception(
            f'{binary_name} not found in system PATH'
        )

    print(f'{binary_name} found: {binary_path}')

    # ==========================================
    # DATABASE CONNECTION
    # ==========================================

    conn = connect_db()

    cursor = conn.cursor()

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

        print()
        print(
            f'Remediating {package_name} -> {recommended_version}'
        )

        # ==========================================
        # BUILD DYNAMIC COMMAND
        # ==========================================

        command = manager_commands[
            package_manager
        ]["command_builder"](
            package_name,
            recommended_version
        )

        print(f'Executing: {" ".join(command)}')

        # ==========================================
        # EXECUTE REMEDIATION
        # ==========================================

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

    # ==========================================
    # COMMIT RESULTS
    # ==========================================

    conn.commit()

    print()
    print(f'Remediated: {remediated}')
    print(f'Failed: {failed}')

    cursor.close()
    conn.close()

except Exception as e:

    print(f'Error: {e}')

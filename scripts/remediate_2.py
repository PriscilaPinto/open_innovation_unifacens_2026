"""
STAGE 3 - Aplicação de Remediações
Executa composer/npm/pip para atualizar dependências aprovadas.
Salva versão anterior para permitir rollback.
"""
import subprocess
import shutil
import os
from dotenv import load_dotenv
from db import connect_db
from context_collector import detect_ecosystem

load_dotenv()

COMMANDS = {
    "composer": lambda pkg, ver: ["composer", "require", f"{pkg}:{ver}", "--no-interaction"],
    "npm":      lambda pkg, ver: ["npm", "install", f"{pkg}@{ver}"],
    "pip":      lambda pkg, ver: ["pip", "install", f"{pkg}=={ver}"],
}


def main():
    context = detect_ecosystem()
    pm = context.get("package_manager")
    print(f"Ecosystem: {context.get('ecosystem')} | Package manager: {pm}")

    if pm not in COMMANDS:
        raise SystemExit(f"❌ Package manager não suportado: {pm}")

    binary = shutil.which(pm)
    if binary is None:
        raise SystemExit(f"❌ {pm} não encontrado no PATH")
    print(f"{pm} encontrado: {binary}\n")

    conn = connect_db()
    cursor = conn.cursor()

    # Busca apenas um registro por pacote com APPROVED para evitar execução duplicada
    cursor.execute("""
        SELECT DISTINCT ON (package_name)
            id, package_name, installed_version, recommended_version
        FROM vulnerability_records
        WHERE decision_status = 'APPROVED'
          AND remediation_status = 'OPEN'
        ORDER BY package_name
    """)
    rows = cursor.fetchall()

    if not rows:
        print("Nenhuma vulnerabilidade aprovada para remediar.")
        cursor.close()
        conn.close()
        return

    remediated = failed = 0

    for vuln_id, pkg, old_version, new_version in rows:
        print(f"🔧 {pkg}: {old_version} → {new_version}")
        cmd = COMMANDS[pm](pkg, new_version)
        print(f"   Executando: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"   ✅ Sucesso")
            # Marca TODAS as CVEs do pacote como REMEDIATED e salva versão anterior para rollback
            cursor.execute("""
                UPDATE vulnerability_records
                SET remediation_status = 'REMEDIATED',
                    previous_version = installed_version,
                    updated_at = NOW()
                WHERE package_name = %s
                  AND decision_status = 'APPROVED'
                  AND remediation_status = 'OPEN'
            """, (pkg,))
            remediated += 1
        else:
            print(f"   ❌ Falha: {result.stderr[:200]}")
            cursor.execute("""
                UPDATE vulnerability_records
                SET remediation_status = 'FAILED', updated_at = NOW()
                WHERE package_name = %s
                  AND decision_status = 'APPROVED'
                  AND remediation_status = 'OPEN'
            """, (pkg,))
            failed += 1

    conn.commit()
    print(f"\nRemediated: {remediated} | Failed: {failed}")
    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()

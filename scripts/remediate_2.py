"""
STAGE 3 - Aplicação de Remediações (Multi-Linguagem)
Executa composer/npm/pip para atualizar dependências aprovadas.
Salva versão anterior para permitir rollback.

NOVO: Processa CADA LINGUAGEM separadamente usando coluna ecosystem do BD!
"""
import subprocess
import shutil
import os
from dotenv import load_dotenv
from db import connect_db
from context_collector import detect_ecosystems

load_dotenv()

COMMANDS = {
    "composer": lambda pkg, ver: ["composer", "require", f"{pkg}:{ver}", "--no-interaction"],
    "npm":      lambda pkg, ver: ["npm", "install", f"{pkg}@{ver}"],
    "pip":      lambda pkg, ver: ["pip", "install", f"{pkg}=={ver}"],
}

PACKAGE_MANAGERS = {
    "PHP": "composer",
    "Node.js": "npm",
    "Python": "pip",
}


def main():
    """
    Multi-linguagem: usa coluna ecosystem do BD para agrupar vulnerabilidades.
    Processa cada linguagem com seu gerenciador específico.
    """
    conn = connect_db()
    cursor = conn.cursor()
    
    # Busca TODOS os ecossistemas com vulnerabilidades aprovadas
    cursor.execute("""
        SELECT DISTINCT ecosystem
        FROM vulnerability_records
        WHERE decision_status = 'APPROVED'
          AND remediation_status = 'OPEN'
          AND ecosystem != 'UNKNOWN'
        ORDER BY ecosystem
    """)
    
    ecosystems = [row[0] for row in cursor.fetchall()]
    
    if not ecosystems:
        print("✅ Nenhuma vulnerabilidade aprovada para remediar.")
        cursor.close()
        conn.close()
        return
    
    print(f"\n🌍 Detectados {len(ecosystems)} ecossistema(s) com vulnerabilidades: {', '.join(ecosystems)}")
    
    remediated_total = 0
    failed_total = 0

    # Processa CADA ecossistema
    for ecosystem in ecosystems:
        pm = PACKAGE_MANAGERS.get(ecosystem)
        if not pm:
            print(f"❌ Ecossistema desconhecido: {ecosystem}")
            continue
        
        print(f"\n{'='*60}")
        print(f"🔧 Processando {ecosystem} (gerenciador: {pm})")
        print(f"{'='*60}")

        binary = shutil.which(pm)
        if not binary:
            print(f"❌ {pm} não encontrado no PATH — pulando {ecosystem}")
            continue

        # Busca vulnerabilidades APPROVED DESTE ECOSSISTEMA
        cursor.execute("""
            SELECT DISTINCT ON (package_name)
                id, package_name, installed_version, recommended_version
            FROM vulnerability_records
            WHERE decision_status = 'APPROVED'
              AND remediation_status = 'OPEN'
              AND ecosystem = %s
            ORDER BY package_name
        """, (ecosystem,))
        
        records = cursor.fetchall()

        if not records:
            print(f"✅ Nenhuma vulnerabilidade aprovada para {ecosystem}")
            continue

        remediated = failed = 0

        for vuln_id, pkg, old_version, new_version in records:
            print(f"\n  🔧 {pkg}: {old_version} → {new_version}")
            cmd = COMMANDS[pm](pkg, new_version)
            print(f"     Executando: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"     ✅ Sucesso")
                # Marca como REMEDIATED
                cursor.execute("""
                    UPDATE vulnerability_records
                    SET remediation_status = 'REMEDIATED',
                        previous_version = installed_version,
                        updated_at = NOW()
                    WHERE package_name = %s
                      AND ecosystem = %s
                      AND decision_status = 'APPROVED'
                      AND remediation_status = 'OPEN'
                """, (pkg, ecosystem))
                remediated += 1
            else:
                print(f"     ❌ Falha: {result.stderr[:200]}")
                cursor.execute("""
                    UPDATE vulnerability_records
                    SET remediation_status = 'FAILED', updated_at = NOW()
                    WHERE package_name = %s
                      AND ecosystem = %s
                      AND decision_status = 'APPROVED'
                      AND remediation_status = 'OPEN'
                """, (pkg, ecosystem))
                failed += 1

        conn.commit()
        
        print(f"\n  ✅ {ecosystem}: {remediated} remediadas | {failed} falhas")
        remediated_total += remediated
        failed_total += failed

    cursor.close()
    conn.close()
    
    print(f"\n{'='*60}")
    print(f"📊 TOTAL: {remediated_total} remediadas | {failed_total} falhas")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

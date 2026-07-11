"""
Framework de Remediação Automática de Vulnerabilidades
Orquestra: persist_history → decision_engine → remediate_2
"""
import os
import subprocess
import sys
from dotenv import load_dotenv

load_dotenv()

STAGES = [
    ("📊 STAGE 1 - Persistência e Enriquecimento", "scripts/persist_history.py"),
    ("🤖 STAGE 2 - Engine de Decisão",             "scripts/decision_engine.py"),
    ("🔧 STAGE 3 - Aplicação de Remediações",      "scripts/remediate_2.py"),
]


def run_stage(label, script):
    print(f"\n{label}")
    print("-" * 60)
    result = subprocess.run([sys.executable, script], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f"❌ Erro em {script}:")
        print(result.stderr)
        sys.exit(1)


def main():
    print("\n" + "=" * 60)
    print("🔒 FRAMEWORK DE REMEDIAÇÃO AUTOMÁTICA")
    print("=" * 60)

    if not os.path.exists("reports/report.json"):
        print("❌ reports/report.json não encontrado.")
        print("   Execute: trivy fs . --format json --output reports/report.json")
        sys.exit(1)

    for label, script in STAGES:
        run_stage(label, script)

    print("\n" + "=" * 60)
    print("✅ PIPELINE CONCLUÍDO COM SUCESSO")
    print("=" * 60)


if __name__ == "__main__":
    main()

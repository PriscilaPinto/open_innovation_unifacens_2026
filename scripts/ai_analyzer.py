"""
Framework de Remediação Automática de Vulnerabilidades
Orquestra todo o fluxo: persist → decision → remediation
"""
import os
import subprocess
import sys
from dotenv import load_dotenv

# Carrega variáveis de ambiente
load_dotenv()

def executar_pipeline_completo():
    """
    Executa o pipeline completo de remediação:
    1. Persiste vulnerabilidades do Trivy no banco
    2. Executa engine de decisão (aprova HIGH/CRITICAL automaticamente)
    3. Aplica remediações aprovadas
    """
    
    print("\n" + "="*60)
    print("🔒 FRAMEWORK DE REMEDIAÇÃO AUTOMÁTICA")
    print("="*60 + "\n")
    
    # Verifica se relatório Trivy existe
    if not os.path.exists('reports/report.json'):
        print("❌ Erro: reports/report.json não encontrado.")
        print("   Execute: trivy fs . --format json --output reports/report.json")
        sys.exit(1)
    
    # Decide qual script de persistência usar
    use_curated_db = os.getenv('USE_CURATED_DB', 'false').lower() == 'true'
    persist_script = "scripts/persist_history_with_curated_db.py" if use_curated_db else "scripts/persist_history.py"
    
    if use_curated_db:
        print("🗄️  Modo: Banco curado + OSV API (fallback)")
    else:
        print("🌐 Modo: OSV API")
    
    # STAGE 1: Persistir vulnerabilidades no banco
    print("\n📊 [STAGE 1] Persistindo vulnerabilidades no banco de dados...")
    print("-" * 60)
    result = subprocess.run(
        [sys.executable, persist_script],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Erro ao persistir vulnerabilidades:")
        print(result.stderr)
        sys.exit(1)
    
    print(result.stdout)
    
    # STAGE 2: Engine de decisão
    print("\n🤖 [STAGE 2] Executando engine de decisão automática...")
    print("-" * 60)
    result = subprocess.run(
        [sys.executable, "scripts/decision_engine.py"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Erro no engine de decisão:")
        print(result.stderr)
        sys.exit(1)
    
    print(result.stdout)
    
    # STAGE 3: Aplicar remediações
    print("\n🔧 [STAGE 3] Aplicando remediações aprovadas...")
    print("-" * 60)
    result = subprocess.run(
        [sys.executable, "scripts/remediate_2.py"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Erro ao aplicar remediações:")
        print(result.stderr)
        sys.exit(1)
    
    print(result.stdout)
    
    print("\n" + "="*60)
    print("✅ PIPELINE DE REMEDIAÇÃO CONCLUÍDO COM SUCESSO")
    print("="*60 + "\n")
    print("📝 Próximos passos:")
    print("   1. Verifique as mudanças no composer.json/package.json")
    print("   2. Execute testes da aplicação")
    print("   3. Commit e push para abrir PR automático")


if __name__ == "__main__":
    executar_pipeline_completo()

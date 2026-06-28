"""
Script para importar logs de auditoria do GitHub Actions para banco local
Uso: python scripts/import_audit_from_github.py audit_logs/
"""
import os
import sys
import csv
import json
import psycopg2
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()


def connect_db():
    """Conecta ao banco PostgreSQL local"""
    return psycopg2.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 5432)),
        database=os.getenv('DB_NAME', 'remediation'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', 'postgres')
    )


def import_pipeline_executions(conn, csv_path):
    """Importa execuções do pipeline"""
    cursor = conn.cursor()
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            cursor.execute("""
                INSERT INTO pipeline_executions (
                    id, repository_name, workflow_run_id, 
                    started_at, finished_at, status,
                    vulnerabilities_found, vulnerabilities_resolved,
                    reduction_percentage
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                row['id'],
                row['repository_name'],
                row['workflow_run_id'],
                row['started_at'],
                row.get('finished_at'),
                row['status'],
                int(row['vulnerabilities_found']) if row.get('vulnerabilities_found') else 0,
                int(row['vulnerabilities_resolved']) if row.get('vulnerabilities_resolved') else 0,
                float(row['reduction_percentage']) if row.get('reduction_percentage') else 0
            ))
    
    conn.commit()
    print(f"✅ Importado: {csv_path}")


def import_vulnerability_records(conn, csv_path):
    """Importa registros de vulnerabilidades"""
    cursor = conn.cursor()
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            cursor.execute("""
                INSERT INTO vulnerability_records (
                    id, execution_id, cve_id, package_name,
                    severity, installed_version, fixed_version,
                    recommended_version, osv_reference,
                    decision_status, remediation_status,
                    created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                row['id'],
                row['execution_id'],
                row.get('cve_id'),
                row['package_name'],
                row['severity'],
                row['installed_version'],
                row.get('fixed_version'),
                row.get('recommended_version'),
                row.get('osv_reference'),
                row.get('decision_status'),
                row.get('remediation_status'),
                row['created_at'],
                row['updated_at']
            ))
    
    conn.commit()
    print(f"✅ Importado: {csv_path}")


def main():
    if len(sys.argv) < 2:
        print("Uso: python scripts/import_audit_from_github.py <pasta_audit_logs>")
        print("Exemplo: python scripts/import_audit_from_github.py audit_logs/")
        sys.exit(1)
    
    audit_dir = Path(sys.argv[1])
    
    if not audit_dir.exists():
        print(f"❌ Erro: Pasta '{audit_dir}' não encontrada")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("📥 IMPORTANDO AUDITORIA DO GITHUB ACTIONS")
    print("="*60 + "\n")
    
    conn = connect_db()
    
    # Importar execuções do pipeline
    for csv_file in audit_dir.glob("pipeline_executions_*.csv"):
        import_pipeline_executions(conn, csv_file)
    
    # Importar vulnerabilidades
    for csv_file in audit_dir.glob("vulnerability_records_*.csv"):
        import_vulnerability_records(conn, csv_file)
    
    conn.close()
    
    print("\n" + "="*60)
    print("✅ IMPORTAÇÃO CONCLUÍDA")
    print("="*60 + "\n")
    print("Consulte os dados:")
    print("  docker exec -it remediation-db psql -U postgres -d remediation")
    print("  SELECT COUNT(*) FROM vulnerability_records;")


if __name__ == "__main__":
    main()

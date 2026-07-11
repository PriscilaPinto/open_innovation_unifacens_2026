"""
Framework de Remediação Automática de Vulnerabilidades
Executa os 3 stages no mesmo processo Python — sem subprocessos.
"""
import os
import sys
import json
import subprocess
import shutil
import requests
import psycopg2
from dotenv import load_dotenv

load_dotenv()

# Garante que scripts/ está no path para importar db.py e context_collector.py
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

from db import connect_db
from context_collector import detect_ecosystem


# ============================================================
# CONEXÃO COMPARTILHADA
# ============================================================
def get_conn():
    return connect_db()


# ============================================================
# STAGE 1: Persistência e Enriquecimento
# ============================================================
def query_homologated_version(cursor, package_name, ecosystem='PHP'):
    cursor.execute("""
        SELECT safe_version, approved_by
        FROM homologated_versions
        WHERE package_name = %s AND ecosystem = %s
        ORDER BY approved_at DESC LIMIT 1
    """, (package_name, ecosystem))
    row = cursor.fetchone()
    if row:
        return {"source": "CURATED_DB", "recommended_version": row[0], "approved_by": row[1]}
    return None


def query_osv(package_name, version):
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package_name, "ecosystem": "Packagist"}, "version": version},
            timeout=10
        )
        if resp.status_code == 200:
            vulns = resp.json().get("vulns", [])
            if vulns:
                osv_id = vulns[0].get("id")
                for affected in vulns[0].get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                return {"source": "OSV_API", "osv_id": osv_id, "recommended_version": event["fixed"]}
    except Exception as e:
        print(f"  ⚠️  OSV API error: {e}")
    return None


def stage1_persist(conn):
    print("\n📊 STAGE 1 - Persistência e Enriquecimento")
    print("-" * 60)

    cursor = conn.cursor()
    run_id = os.getenv("GITHUB_RUN_ID", "local-run")
    repo   = os.getenv("GITHUB_REPOSITORY", "local")

    cursor.execute("""
        INSERT INTO pipeline_executions
            (repository_name, workflow_run_id, status,
             vulnerabilities_found, vulnerabilities_resolved, reduction_percentage)
        VALUES (%s, %s, %s, 0, 0, 0) RETURNING id
    """, (repo, run_id, "RUNNING"))
    execution_id = cursor.fetchone()[0]
    conn.commit()
    print(f"✅ Execução criada: {execution_id}")

    with open("reports/report.json") as f:
        report = json.load(f)

    count = 0
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            count += 1
            pkg     = vuln.get("PkgName")
            version = vuln.get("InstalledVersion")
            print(f"🔍 {pkg} {version}...")

            vdata = query_homologated_version(cursor, pkg)
            if vdata:
                print(f"  ✅ Banco curado (por: {vdata['approved_by']})")
            else:
                print(f"  ⚠️  Consultando OSV API...")
                vdata = query_osv(pkg, version)
                print(f"  {'✅ OSV API' if vdata else '❌ Não encontrado'}")

            cursor.execute("""
                INSERT INTO vulnerability_records
                    (execution_id, cve_id, package_name, severity,
                     installed_version, fixed_version, remediation_status,
                     osv_reference, recommended_version)
                VALUES (%s,%s,%s,%s,%s,%s,'OPEN',%s,%s)
            """, (
                execution_id,
                vuln.get("VulnerabilityID"),
                pkg,
                vuln.get("Severity"),
                version,
                vuln.get("FixedVersion"),
                vdata.get("osv_id")             if vdata else None,
                vdata.get("recommended_version") if vdata else None,
            ))

    cursor.execute(
        "UPDATE pipeline_executions SET vulnerabilities_found=%s WHERE id=%s",
        (count, execution_id)
    )
    conn.commit()
    print(f"\n✅ Vulnerabilidades salvas: {count}")
    cursor.close()
    return execution_id


# ============================================================
# STAGE 2: Engine de Decisão
# ============================================================
def stage2_decide(conn):
    print("\n🤖 STAGE 2 - Engine de Decisão")
    print("-" * 60)

    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT ON (package_name)
            id, package_name, severity, recommended_version
        FROM vulnerability_records
        WHERE remediation_status = 'OPEN'
          AND decision_status = 'PENDING'
        ORDER BY package_name,
            CASE severity
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5
            END
    """)
    packages = cursor.fetchall()

    approved = manual = ignored = 0
    for _, pkg, severity, recommended_version in packages:
        if severity in ("CRITICAL", "HIGH") and recommended_version:
            decision = "APPROVED";  approved += 1
        elif severity == "LOW":
            decision = "IGNORE";    ignored  += 1
        else:
            decision = "MANUAL_REVIEW"; manual += 1

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


# ============================================================
# STAGE 3: Aplicação de Remediações
# ============================================================
COMMANDS = {
    "composer": lambda pkg, ver: ["composer", "require", f"{pkg}:{ver}", "--no-interaction"],
    "npm":      lambda pkg, ver: ["npm", "install", f"{pkg}@{ver}"],
    "pip":      lambda pkg, ver: ["pip", "install", f"{pkg}=={ver}"],
}


def stage3_remediate(conn):
    print("\n🔧 STAGE 3 - Aplicação de Remediações")
    print("-" * 60)

    context = detect_ecosystem()
    pm = context.get("package_manager")
    print(f"Ecosystem: {context.get('ecosystem')} | Package manager: {pm}")

    if pm not in COMMANDS:
        print(f"❌ Package manager não suportado: {pm}")
        return

    binary = shutil.which(pm)
    if not binary:
        print(f"❌ {pm} não encontrado no PATH")
        return
    print(f"{pm} encontrado: {binary}\n")

    cursor = conn.cursor()
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
        return

    remediated = failed = 0
    for vuln_id, pkg, old_ver, new_ver in rows:
        print(f"🔧 {pkg}: {old_ver} → {new_ver}")
        cmd = COMMANDS[pm](pkg, new_ver)
        print(f"   Executando: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"   ✅ Sucesso")
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
            print(f"   ❌ Falha: {result.stderr[:300]}")
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


# ============================================================
# MAIN
# ============================================================
def main():
    print("\n" + "=" * 60)
    print("🔒 FRAMEWORK DE REMEDIAÇÃO AUTOMÁTICA")
    print("=" * 60)

    if not os.path.exists("reports/report.json"):
        print("❌ reports/report.json não encontrado.")
        sys.exit(1)

    conn = get_conn()
    try:
        stage1_persist(conn)
        stage2_decide(conn)
        stage3_remediate(conn)
    finally:
        conn.close()

    print("\n" + "=" * 60)
    print("✅ PIPELINE CONCLUÍDO COM SUCESSO")
    print("=" * 60)


if __name__ == "__main__":
    main()

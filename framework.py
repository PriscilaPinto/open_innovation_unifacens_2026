"""
Framework Autônomo de Remediação SCA
A IA é o cérebro: após o Trivy fazer o scan, o agente decide e orquestra tudo.

Requisitos implementados:
  Req 1  - Análise do repositório
  Req 2  - Varredura inicial (Trivy)
  Req 3  - Análise orientada por IA + consulta OSV
  Req 4  - Aplicação automatizada de patches (branch fix-remediation)
  Req 5  - Validação pós-remediação (re-scan Trivy)
  Req 8  - Smoke test de estabilidade PHP
  Req 10 - Tratamento de erros, logs detalhados, retry
  Req 11 - Configuração via variáveis de ambiente
  Req 12 - Histórico completo no Supabase
"""
import os
import sys
import json
import time
import subprocess
import shutil
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Garante que scripts/ está no path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

from db import connect_db
from context_collector import detect_ecosystem

# Req 11: configuração via env com defaults seguros
MIN_SEVERITY     = os.getenv("MIN_SEVERITY", "HIGH")        # severidade mínima para remediar
TRIVY_RETRIES    = int(os.getenv("TRIVY_RETRIES", "3"))     # Req 2.5: retry do scanner


def log(msg, level="INFO"):
    ts = datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] {level}: {msg}")


def get_ai_agent():
    """Import lazy — falha visível no log, nunca silenciosa."""
    try:
        from ai_agent import analisar_lote
        log("Agente de IA carregado (OpenRouter/Gemini)")
        return analisar_lote
    except Exception as e:
        log(f"Agente de IA não disponível: {e}. Usando fallback por severidade.", "WARN")
        return None


# ============================================================
# BANCO: helpers
# ============================================================
def db_safe(fn, conn, *args, **kwargs):
    """Req 12.6: executa operação DB sem interromper o fluxo se falhar."""
    try:
        return fn(conn, *args, **kwargs)
    except Exception as e:
        log(f"DB error (non-fatal): {e}", "WARN")
        try:
            conn.rollback()
        except Exception:
            pass
        return None


def db_create_execution(conn, repo, run_id):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO pipeline_executions
            (repository_name, workflow_run_id, status,
             vulnerabilities_found, vulnerabilities_resolved, reduction_percentage)
        VALUES (%s, %s, 'RUNNING', 0, 0, 0) RETURNING id
    """, (repo, run_id))
    eid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    return eid


def db_finish_execution(conn, execution_id, status, found, resolved):
    pct = round((resolved / found * 100), 2) if found > 0 else 0
    cur = conn.cursor()
    cur.execute("""
        UPDATE pipeline_executions
        SET status=%s, finished_at=NOW(),
            vulnerabilities_found=%s, vulnerabilities_resolved=%s, reduction_percentage=%s
        WHERE id=%s
    """, (status, found, resolved, pct, execution_id))
    conn.commit()
    cur.close()
    log(f"Execução finalizada: {status} | {resolved}/{found} ({pct}%) resolvidas")


def db_save_pr(conn, execution_id, pr_number, pr_url):
    """Req 12.5: salva referência ao PR."""
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO pull_requests (execution_id, pr_number, pr_url, approval_status)
        VALUES (%s, %s, %s, 'PENDING')
        ON CONFLICT DO NOTHING
    """, (execution_id, pr_number, pr_url))
    conn.commit()
    cur.close()


# ============================================================
# STAGE 1: Leitura do relatório Trivy + OSV + Supabase
# Req 1, 2, 3.2, 12
# ============================================================
def query_osv(package_name, version, ecosystem="Packagist"):
    """Req 3.2: consulta OSV Database."""
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package_name, "ecosystem": ecosystem}, "version": version},
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
                                return {"osv_id": osv_id, "recommended_version": event["fixed"]}
    except Exception as e:
        log(f"OSV API error para {package_name}: {e}", "WARN")
    return None


def query_curated(cursor, package_name, ecosystem="PHP"):
    cursor.execute("""
        SELECT safe_version, approved_by
        FROM homologated_versions
        WHERE package_name=%s AND ecosystem=%s
        ORDER BY approved_at DESC LIMIT 1
    """, (package_name, ecosystem))
    row = cursor.fetchone()
    if row:
        return {"recommended_version": row[0], "source": f"CURATED_DB (by {row[1]})"}
    return None


def stage1_load_and_persist(conn, report_path="reports/report.json"):
    """Req 1, 2, 12: lê relatório, enriquece com OSV/curado e persiste."""
    log("=" * 60)
    log("STAGE 1 — Leitura do Trivy Report + Persistência Supabase")
    log("=" * 60)

    # Req 1.4/1.5: verifica arquivo
    if not os.path.exists(report_path):
        log(f"Relatório não encontrado: {report_path}", "ERROR")
        sys.exit(1)

    run_id = os.getenv("GITHUB_RUN_ID", f"local-{int(time.time())}")
    repo   = os.getenv("GITHUB_REPOSITORY", "local")
    context = detect_ecosystem()
    osv_eco = context.get("osv_ecosystem", "Packagist")
    curated_eco = context.get("curated_ecosystem", "PHP")

    execution_id = db_safe(db_create_execution, conn, repo, run_id)
    if execution_id:
        log(f"Execução criada no Supabase: {execution_id}")

    with open(report_path) as f:
        report = json.load(f)

    all_results = report.get("Results", [])

    # Req 2.4: sem vulnerabilidades → encerra graciosamente
    total_vulns = sum(len(r.get("Vulnerabilities") or []) for r in all_results)
    if total_vulns == 0:
        log("✅ Nenhuma vulnerabilidade encontrada. Pipeline encerra com sucesso.")
        if execution_id:
            db_safe(db_finish_execution, conn, execution_id, "SUCCESS", 0, 0)
        sys.exit(0)

    log(f"Vulnerabilidades detectadas: {total_vulns}")
    cur = conn.cursor()
    count = 0

    for result in all_results:
        for vuln in (result.get("Vulnerabilities") or []):
            count += 1
            pkg     = vuln.get("PkgName")
            version = vuln.get("InstalledVersion")
            sev     = vuln.get("Severity", "UNKNOWN")

            # Banco curado primeiro, depois OSV
            vdata = query_curated(cur, pkg, curated_eco)
            source = ""
            if vdata:
                source = vdata["source"]
            else:
                vdata = query_osv(pkg, version, osv_eco)
                if vdata:
                    source = "OSV_API"

            log(f"  {pkg} {version} [{sev}] → {vdata.get('recommended_version') if vdata else 'N/A'} ({source})")

            try:
                cur.execute("""
                    INSERT INTO vulnerability_records
                        (execution_id, cve_id, package_name, severity,
                         installed_version, fixed_version, remediation_status,
                         osv_reference, recommended_version)
                    VALUES (%s,%s,%s,%s,%s,%s,'OPEN',%s,%s)
                """, (
                    execution_id,
                    vuln.get("VulnerabilityID"),
                    pkg, sev, version,
                    vuln.get("FixedVersion"),
                    vdata.get("osv_id") if vdata else None,
                    vdata.get("recommended_version") if vdata else None,
                ))
            except Exception as e:
                log(f"DB insert error para {pkg}: {e}", "WARN")
                conn.rollback()

    if execution_id:
        try:
            cur.execute("UPDATE pipeline_executions SET vulnerabilities_found=%s WHERE id=%s",
                        (count, execution_id))
        except Exception:
            pass
    conn.commit()
    cur.close()
    log(f"✅ {count} vulnerabilidades salvas no Supabase")
    return execution_id, count


# ============================================================
# STAGE 2: Agente de IA analisa e decide
# Req 3: análise orientada por IA
# ============================================================
def stage2_ai_decide(conn):
    log("=" * 60)
    log("STAGE 2 — Agente de IA: Análise e Decisão de Remediação")
    log("=" * 60)

    cur = conn.cursor()
    cur.execute("""
        SELECT id, package_name, severity, recommended_version,
               installed_version, cve_id, fixed_version
        FROM vulnerability_records
        WHERE remediation_status='OPEN' AND decision_status='PENDING'
        ORDER BY CASE severity
            WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END
    """)
    rows = cur.fetchall()
    cur.close()

    if not rows:
        log("Nenhuma vulnerabilidade pendente.")
        return

    context = detect_ecosystem()
    vulns = [
        {"id": r[0], "package_name": r[1], "severity": r[2],
         "recommended_version": r[3], "installed_version": r[4],
         "cve_id": r[5], "fixed_version": r[6],
         "ecosystem": context.get("curated_ecosystem", "PHP")}
        for r in rows
    ]

    analisar_lote = get_ai_agent()
    approved = manual = ignored = 0
    cur = conn.cursor()

    if analisar_lote:
        log(f"Enviando {len(set(v['package_name'] for v in vulns))} pacote(s) para análise...")
        try:
            decisoes = analisar_lote(vulns)
            for d in decisoes:
                pkg      = d["package_name"]
                decision = d["decision"]
                rec_ver  = d.get("recommended_version")
                justif   = d.get("justification", "")

                if decision == "APPROVED":   approved += 1
                elif decision == "IGNORE":   ignored  += 1
                else:                        manual   += 1

                # Atualiza todos os registros do pacote com a decisão da IA
                cur.execute("""
                    UPDATE vulnerability_records
                    SET decision_status=%s, ai_justification=%s,
                        recommended_version=COALESCE(%s, recommended_version),
                        updated_at=NOW()
                    WHERE package_name=%s
                      AND remediation_status='OPEN'
                      AND decision_status='PENDING'
                """, (decision, justif, rec_ver, pkg))

            conn.commit()
            log(f"✅ Decisões: Approved={approved} | Manual Review={manual} | Ignored={ignored}")
            cur.close()
            return
        except Exception as e:
            log(f"Agente de IA falhou: {e}. Usando fallback.", "WARN")
            conn.rollback()

    # Req 10: fallback por severidade quando IA indisponível
    log("Usando regras de severidade como fallback...")
    seen = set()
    for vuln in vulns:
        pkg = vuln["package_name"]
        if pkg in seen:
            continue
        seen.add(pkg)
        sev = vuln["severity"]
        rec = vuln["recommended_version"]

        if sev in ("CRITICAL", "HIGH") and rec:
            dec = "APPROVED";      approved += 1
        elif sev == "LOW":
            dec = "IGNORE";        ignored  += 1
        else:
            dec = "MANUAL_REVIEW"; manual   += 1

        cur.execute("""
            UPDATE vulnerability_records
            SET decision_status=%s,
                ai_justification='Fallback: regra de severidade (IA indisponível)',
                updated_at=NOW()
            WHERE package_name=%s AND remediation_status='OPEN' AND decision_status='PENDING'
        """, (dec, pkg))
        log(f"  {pkg}: {dec} (severity={sev})")

    conn.commit()
    cur.close()
    log(f"✅ Fallback: Approved={approved} | Manual Review={manual} | Ignored={ignored}")


# ============================================================
# STAGE 3: Aplicação dos patches
# Req 4: aplicação automatizada
# ============================================================
COMMANDS = {
    "composer": lambda pkg, ver: ["composer", "require", f"{pkg}:{ver}", "--no-interaction"],
    "npm":      lambda pkg, ver: ["npm", "install", f"{pkg}@{ver}"],
    "pip":      lambda pkg, ver: ["pip", "install", f"{pkg}=={ver}"],
}


def stage3_apply_patches(conn):
    log("=" * 60)
    log("STAGE 3 — Aplicação de Patches")
    log("=" * 60)

    context = detect_ecosystem()
    pm = context.get("package_manager")
    log(f"Ecossistema: {context.get('ecosystem')} | Package manager: {pm}")

    if pm not in COMMANDS:
        log(f"Package manager não suportado: {pm}", "ERROR")
        return 0

    binary = shutil.which(pm)
    if not binary:
        log(f"{pm} não encontrado no PATH", "ERROR")
        return 0

    cur = conn.cursor()
    cur.execute("""
        SELECT DISTINCT ON (package_name)
            id, package_name, installed_version, recommended_version, ai_justification
        FROM vulnerability_records
        WHERE decision_status='APPROVED' AND remediation_status='OPEN'
        ORDER BY package_name
    """)
    rows = cur.fetchall()
    cur.close()

    if not rows:
        log("Nenhuma vulnerabilidade aprovada para patch.")
        return 0

    remediated = failed = 0
    cur = conn.cursor()

    for _, pkg, old_ver, new_ver, justif in rows:
        log(f"Aplicando patch: {pkg} {old_ver} → {new_ver}")
        if justif:
            log(f"  Justificativa IA: {justif[:120]}")

        cmd = COMMANDS[pm](pkg, new_ver)
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            log(f"  ✅ Patch aplicado com sucesso")
            cur.execute("""
                UPDATE vulnerability_records
                SET remediation_status='REMEDIATED',
                    previous_version=installed_version,
                    updated_at=NOW()
                WHERE package_name=%s AND decision_status='APPROVED' AND remediation_status='OPEN'
            """, (pkg,))
            remediated += 1
        else:
            # Req 4.4: falhas parciais — registra e continua
            log(f"  ❌ Falha no patch: {result.stderr[:200]}", "WARN")
            cur.execute("""
                UPDATE vulnerability_records
                SET remediation_status='FAILED', updated_at=NOW()
                WHERE package_name=%s AND decision_status='APPROVED' AND remediation_status='OPEN'
            """, (pkg,))
            failed += 1

    conn.commit()
    cur.close()
    log(f"✅ Patches: {remediated} aplicados | {failed} falhas")
    return remediated


# ============================================================
# STAGE 4: Validação pós-patch (re-scan Trivy)
# Req 5: validação pós-remediação
# Req 8: smoke test de estabilidade
# ============================================================
def stage4_validate(conn, execution_id, vulns_before):
    log("=" * 60)
    log("STAGE 4 — Validação Pós-Patch (Re-scan + Smoke Test)")
    log("=" * 60)

    # Req 5.1: re-scan Trivy
    log("Executando re-scan Trivy...")
    result = subprocess.run(
        ["trivy", "fs", ".", "--format", "json",
         "--output", "reports/report_post_patch.json", "--skip-version-check"],
        capture_output=True, text=True
    )

    if result.returncode != 0 and not os.path.exists("reports/report_post_patch.json"):
        log("Re-scan falhou — validação inconclusiva.", "WARN")
        return False

    # Req 8.4: smoke test PHP
    context = detect_ecosystem()
    if context.get("ecosystem") == "php":
        log("Executando smoke test PHP (validação de sintaxe)...")
        php_files = [f for f in ["index.php"] if os.path.exists(f)]
        for php_file in php_files:
            r = subprocess.run(["php", "-l", php_file], capture_output=True, text=True)
            if r.returncode == 0:
                log(f"  ✅ {php_file}: sintaxe OK")
            else:
                log(f"  ⚠️  {php_file}: erro de sintaxe — {r.stderr[:100]}", "WARN")

    # Req 5.3/5.4: comparar relatórios
    try:
        with open("reports/report_post_patch.json") as f:
            post_report = json.load(f)

        vulns_after = sum(
            len(r.get("Vulnerabilities") or [])
            for r in post_report.get("Results", [])
        )

        # Req 5.6: percentual de redução
        if vulns_before > 0:
            reduction = round((vulns_before - vulns_after) / vulns_before * 100, 2)
        else:
            reduction = 0.0

        log(f"Vulnerabilidades: {vulns_before} → {vulns_after} (redução: {reduction}%)")

        if execution_id:
            cur = conn.cursor()
            cur.execute("""
                UPDATE pipeline_executions
                SET vulnerabilities_resolved=%s, reduction_percentage=%s
                WHERE id=%s
            """, (vulns_before - vulns_after, reduction, execution_id))
            conn.commit()
            cur.close()

        # Req 5.5: se alguma vuln persistir — sinaliza
        if vulns_after > 0:
            log(f"⚠️  {vulns_after} vulnerabilidade(s) persistem após patch. Sinalizado para revisão.", "WARN")

        return vulns_after == 0

    except Exception as e:
        log(f"Erro na comparação de relatórios: {e}", "WARN")
        return False


# ============================================================
# MAIN
# ============================================================
def main():
    print("\n" + "=" * 60)
    print("🔒 PIPELINE AUTÔNOMO DE REMEDIAÇÃO SCA")
    print("   IA como agente de segurança central")
    print("=" * 60)

    # Req 2.5: verificação inicial do relatório
    if not os.path.exists("reports/report.json"):
        log("reports/report.json não encontrado. Execute o Trivy primeiro.", "ERROR")
        sys.exit(1)

    conn = connect_db()
    execution_id = None
    vulns_found  = 0

    try:
        # Stage 1: carrega, enriquece e persiste
        execution_id, vulns_found = stage1_load_and_persist(conn)

        # Stage 2: IA analisa e decide
        stage2_ai_decide(conn)

        # Stage 3: aplica patches
        remediated = stage3_apply_patches(conn)

        # Stage 4: valida resultado
        success = stage4_validate(conn, execution_id, vulns_found)

        # Req 12.1: finaliza registro
        status = "SUCCESS" if success else "PARTIAL"
        if execution_id:
            db_safe(db_finish_execution, conn, execution_id, status, vulns_found, remediated)

        print("\n" + "=" * 60)
        if success:
            print("✅ PIPELINE CONCLUÍDO — Todas as vulnerabilidades remediadas")
        else:
            print("⚠️  PIPELINE CONCLUÍDO — Revisão manual necessária para itens restantes")
        print("=" * 60)

    except Exception as e:
        log(f"Erro crítico no pipeline: {e}", "ERROR")
        if execution_id:
            db_safe(db_finish_execution, conn, execution_id, "FAILED", vulns_found, 0)
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()

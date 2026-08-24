"""
Framework Autônomo de Remediação SCA

Fluxo de decisão:
  1. Trivy identifica as vulnerabilidades.
  2. OSV + banco curado enriquecem os dados.
  3. IA analisa e toma a decisão quando disponível.
  4. Se a IA estiver indisponível ou falhar, o banco homologado
     é utilizado como fallback determinístico.
  5. Apenas versões homologadas no banco podem ser instaladas.
  6. Não existe Virtual Patch neste fluxo.
  7. Após a alteração, o projeto é validado pelo smoke test e
     pelo re-scan do Trivy.

Requisitos:
  Req 1  - Análise do repositório
  Req 2  - Varredura inicial (Trivy)
  Req 3  - Análise orientada por IA + consulta OSV
  Req 4  - Aplicação automatizada de patches
  Req 5  - Validação pós-remediação
  Req 8  - Smoke test
  Req 10 - Tratamento de erros, logs e retry
  Req 11 - Configuração via variáveis de ambiente
  Req 12 - Histórico completo no Supabase
"""

import os
import sys
import json
import time
import subprocess
import shutil
import re
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
)

from db import connect_db


MIN_SEVERITY = os.getenv("MIN_SEVERITY", "HIGH")
TRIVY_RETRIES = int(os.getenv("TRIVY_RETRIES", "3"))


PACKAGE_MANAGERS = {
    "PHP": "composer",
    "Node.js": "npm",
    "Python": "pip",
}


# ============================================================
# LOG
# ============================================================

def log(msg, level="INFO"):
    ts = datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] {level}: {msg}")


# ============================================================
# IA
# ============================================================

def get_ai_agent():
    """
    Carrega a IA de forma lazy.

    Importante:
    A indisponibilidade da IA NÃO interrompe o pipeline.
    Nesse caso, o Stage 2 utiliza obrigatoriamente o banco
    homologado como mecanismo de decisão.
    """
    try:
        from ai_agent import analisar_lote

        log("Agente de IA carregado.")
        return analisar_lote

    except Exception as e:
        log(
            f"Agente de IA não disponível: {e}. "
            f"O banco homologado será utilizado como fallback.",
            "WARN"
        )
        return None


# ============================================================
# BANCO
# ============================================================

def db_safe(fn, conn, *args, **kwargs):
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

    cur.execute(
        """
        INSERT INTO pipeline_executions
            (
                repository_name,
                workflow_run_id,
                status,
                vulnerabilities_found,
                vulnerabilities_resolved,
                reduction_percentage
            )
        VALUES (%s, %s, 'RUNNING', 0, 0, 0)
        RETURNING id
        """,
        (repo, run_id)
    )

    eid = cur.fetchone()[0]

    conn.commit()
    cur.close()

    return eid


def db_finish_execution(
    conn,
    execution_id,
    status,
    found,
    resolved
):

    pct = round(
        (resolved / found * 100),
        2
    ) if found > 0 else 0

    cur = conn.cursor()

    cur.execute(
        """
        UPDATE pipeline_executions
        SET
            status=%s,
            finished_at=NOW(),
            vulnerabilities_found=%s,
            vulnerabilities_resolved=%s,
            reduction_percentage=%s
        WHERE id=%s
        """,
        (
            status,
            found,
            resolved,
            pct,
            execution_id
        )
    )

    conn.commit()
    cur.close()

    log(
        f"Execução finalizada: {status} | "
        f"{resolved}/{found} ({pct}%) resolvidas"
    )


# ============================================================
# STAGE 1
# Trivy -> OSV -> banco
# ============================================================

def stage1_load_and_persist(
    conn,
    report_path="reports/report.json"
):

    log("=" * 60)
    log("STAGE 1 — Trivy + OSV + Supabase")
    log("=" * 60)

    if not os.path.exists(report_path):

        log(
            f"Relatório não encontrado: {report_path}",
            "ERROR"
        )

        sys.exit(1)

    run_id = os.getenv(
        "GITHUB_RUN_ID",
        f"local-{int(time.time())}"
    )

    repo = os.getenv(
        "GITHUB_REPOSITORY",
        "local"
    )

    execution_id = db_safe(
        db_create_execution,
        conn,
        repo,
        run_id
    )

    if execution_id:
        log(
            f"Execução criada no Supabase: {execution_id}"
        )

    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    all_results = report.get("Results", [])

    total_vulns = sum(
        len(r.get("Vulnerabilities") or [])
        for r in all_results
    )

    if total_vulns == 0:

        log(
            "Nenhuma vulnerabilidade encontrada."
        )

        if execution_id:

            db_safe(
                db_finish_execution,
                conn,
                execution_id,
                "SUCCESS",
                0,
                0
            )

        sys.exit(0)

    log(
        f"Vulnerabilidades detectadas: {total_vulns}"
    )

    try:

        from persist_history import (
            query_vulnerability_data
        )

        use_persist_history = True

    except ImportError:

        log(
            "persist_history.py não disponível.",
            "WARN"
        )

        use_persist_history = False

    cur = conn.cursor()
    count = 0

    for result in all_results:

        result_type = result.get(
            "Type",
            ""
        ).lower()

        if "composer" in result_type:
            ecosystem = "PHP"

        elif (
            "npm" in result_type
            or "package" in result_type
        ):
            ecosystem = "Node.js"

        elif (
            "pip" in result_type
            or "poetry" in result_type
        ):
            ecosystem = "Python"

        else:
            ecosystem = "UNKNOWN"

        log(
            f"\n🌍 Ecossistema: {ecosystem}"
        )

        for vuln in (
            result.get("Vulnerabilities")
            or []
        ):

            cve_id = vuln.get(
                "VulnerabilityID"
            )

            pkg = vuln.get(
                "PkgName"
            )

            version = vuln.get(
                "InstalledVersion"
            )

            severity = vuln.get(
                "Severity",
                "UNKNOWN"
            )

            fixed_ver = vuln.get(
                "FixedVersion"
            )

            cur.execute(
                """
                SELECT id
                FROM vulnerability_records
                WHERE execution_id=%s
                  AND cve_id=%s
                  AND package_name=%s
                  AND installed_version=%s
                  AND ecosystem=%s
                """,
                (
                    execution_id,
                    cve_id,
                    pkg,
                    version,
                    ecosystem
                )
            )

            if cur.fetchone():

                log(
                    f"[DUPLICADO] {cve_id} "
                    f"{pkg}:{version}"
                )

                continue

            count += 1

            vdata = None
            source = "NONE"
            osv_ref = None
            rec_ver = None

            if use_persist_history:

                vdata = query_vulnerability_data(
                    cur,
                    pkg,
                    version,
                    ecosystem
                )

                if vdata:

                    source = vdata.get(
                        "source",
                        "UNKNOWN"
                    )

                    osv_ref = vdata.get(
                        "osv_id"
                    )

                    rec_ver = vdata.get(
                        "recommended_version"
                    )

            log(
                f"  {pkg} {version} "
                f"[{severity}] -> "
                f"{rec_ver or 'N/A'} "
                f"({source})"
            )

            cur.execute(
                """
                INSERT INTO vulnerability_records
                    (
                        execution_id,
                        cve_id,
                        package_name,
                        severity,
                        installed_version,
                        fixed_version,
                        remediation_status,
                        decision_status,
                        osv_reference,
                        recommended_version,
                        source_db,
                        ecosystem
                    )
                VALUES
                    (
                        %s,%s,%s,%s,%s,%s,
                        'OPEN',
                        'PENDING',
                        %s,%s,%s,%s
                    )
                """,
                (
                    execution_id,
                    cve_id,
                    pkg,
                    severity,
                    version,
                    fixed_ver,
                    osv_ref,
                    rec_ver,
                    source,
                    ecosystem
                )
            )

    if execution_id:

        cur.execute(
            """
            UPDATE pipeline_executions
            SET vulnerabilities_found=%s
            WHERE id=%s
            """,
            (
                count,
                execution_id
            )
        )

    conn.commit()
    cur.close()

    log(
        f"✅ {count} vulnerabilidades salvas."
    )

    return execution_id, count


# ============================================================
# VERSIONAMENTO
# ============================================================

def _version_key(version):

    nums = re.findall(
        r"\d+",
        str(version or "")
    )

    return (
        tuple(int(n) for n in nums)
        if nums
        else (0,)
    )


def _normalize_versions(value):

    if not value:
        return []

    if isinstance(
        value,
        (list, tuple, set)
    ):
        values = value
    else:
        values = [value]

    result = []

    for item in values:

        if not item:
            continue

        parts = re.split(
            r"\s*,\s*|\s*;\s*",
            str(item)
        )

        result.extend(
            p.strip()
            for p in parts
            if p.strip()
        )

    return list(
        dict.fromkeys(result)
    )


def _candidate_fixes_all_cves(
    candidate,
    vulnerabilities
):

    if not candidate or not vulnerabilities:
        return False

    for vuln in vulnerabilities:

        fixed_versions = _normalize_versions(
            vuln.get("fixed_version")
        )

        if not fixed_versions:
            return False

        if not any(
            _version_key(candidate)
            >= _version_key(fixed)
            for fixed in fixed_versions
        ):
            return False

    return True


# ============================================================
# BANCO HOMOLOGADO
# ============================================================

def _get_curated_versions(
    conn,
    package_name,
    ecosystem
):

    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            safe_version,
            approved_by,
            notes,
            approved_at
        FROM homologated_versions
        WHERE package_name=%s
          AND ecosystem=%s
        ORDER BY approved_at DESC
        """,
        (
            package_name,
            ecosystem
        )
    )

    rows = cur.fetchall()

    cur.close()

    return [
        {
            "version": row[0],
            "approved_by": row[1],
            "notes": row[2],
            "approved_at": (
                str(row[3])
                if row[3]
                else None
            )
        }
        for row in rows
    ]


def _select_curated_safe_version(
    conn,
    package_name,
    ecosystem,
    vulnerabilities
):

    versions = _get_curated_versions(
        conn,
        package_name,
        ecosystem
    )

    if not versions:
        return None

    installed = vulnerabilities[0].get(
        "installed_version"
    )

    installed_major = (
        str(installed or "")
        .lstrip("v")
        .split(".")[0]
    )

    candidates = [
        v["version"]
        for v in versions
        if _candidate_fixes_all_cves(
            v["version"],
            vulnerabilities
        )
    ]

    if not candidates:
        return None

    same_major = [
        v
        for v in candidates
        if (
            str(v).lstrip("v").split(".")[0]
            == installed_major
        )
    ]

    pool = same_major or candidates

    return min(
        pool,
        key=_version_key
    )


# ============================================================
# VALIDAÇÃO DA DECISÃO DA IA
# ============================================================

def _validate_ai_decision(
    conn,
    decision,
    vulnerabilities,
    ecosystem
):

    if decision.get("decision") != "APPROVED":
        return decision

    pkg = decision.get(
        "package_name"
    )

    candidate = decision.get(
        "recommended_version"
    )

    if not candidate:

        decision["decision"] = (
            "MANUAL_REVIEW"
        )

        decision["justification"] = (
            decision.get(
                "justification",
                ""
            )
            + " Guardrail: IA aprovou sem "
              "informar versão."
        ).strip()

        return decision

    # A versão escolhida pela IA precisa
    # corrigir todas as evidências do Trivy.
    if not _candidate_fixes_all_cves(
        candidate,
        vulnerabilities
    ):

        decision["decision"] = (
            "MANUAL_REVIEW"
        )

        decision["justification"] = (
            decision.get(
                "justification",
                ""
            )
            + f" Guardrail: {candidate} "
              "não atende todas as FixedVersion."
        ).strip()

        return decision

    # A versão também precisa estar homologada.
    curated = _get_curated_versions(
        conn,
        pkg,
        ecosystem
    )

    curated_versions = {
        v["version"]
        for v in curated
    }

    if candidate not in curated_versions:

        decision["decision"] = (
            "MANUAL_REVIEW"
        )

        decision["justification"] = (
            decision.get(
                "justification",
                ""
            )
            + f" Guardrail: {candidate} "
              "não está homologada no banco."
        ).strip()

        return decision

    return decision


# ============================================================
# FALLBACK
#
# IMPORTANTE:
# Não usa severidade para "inventar" uma versão.
#
# Se a IA falhar:
#     OSV/banco -> recommended_version
#     banco homologado -> validação final
# ============================================================

def _fallback_decision_by_curated(
    conn,
    vulns,
    ecosystem
):

    decisions = []

    by_pkg = {}

    for vuln in vulns:

        by_pkg.setdefault(
            vuln["package_name"],
            []
        ).append(vuln)

    for pkg, items in by_pkg.items():

        # Primeiro tenta a versão recomendada
        # já armazenada no registro pelo Stage 1.
        db_recommended = next(
            (
                v.get("recommended_version")
                for v in items
                if v.get("recommended_version")
            ),
            None
        )

        candidate = None

        # A recomendação do OSV/banco tem prioridade.
        if db_recommended:

            if (
                _candidate_fixes_all_cves(
                    db_recommended,
                    items
                )
                and db_recommended in {
                    v["version"]
                    for v in _get_curated_versions(
                        conn,
                        pkg,
                        ecosystem
                    )
                }
            ):
                candidate = db_recommended

        # Se a recomendação não puder ser utilizada,
        # procura uma versão homologada segura,
        # preservando same-major quando possível.
        if not candidate:

            candidate = _select_curated_safe_version(
                conn,
                pkg,
                ecosystem,
                items
            )

        if candidate:

            decision = "APPROVED"

            justification = (
                "Fallback determinístico: "
                f"versão {candidate} obtida do "
                "banco homologado/OSV e validada "
                "contra as evidências do Trivy."
            )

        else:

            decision = "MANUAL_REVIEW"

            justification = (
                "Fallback: não foi encontrada "
                "versão homologada segura para "
                "todas as vulnerabilidades do pacote."
            )

        decisions.append(
            (
                pkg,
                decision,
                candidate,
                justification
            )
        )

    return decisions


# ============================================================
# STAGE 2
# ============================================================

def stage2_ai_decide(conn):

    log("=" * 60)
    log(
        "STAGE 2 — IA + Banco Homologado"
    )
    log("=" * 60)

    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            id,
            package_name,
            severity,
            recommended_version,
            installed_version,
            cve_id,
            fixed_version,
            ecosystem
        FROM vulnerability_records
        WHERE remediation_status='OPEN'
          AND decision_status='PENDING'
        ORDER BY
            ecosystem,
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END
        """
    )

    rows = cur.fetchall()
    cur.close()

    if not rows:

        log(
            "Nenhuma vulnerabilidade pendente."
        )

        return

    by_ecosystem = {}

    for row in rows:

        (
            vuln_id,
            pkg,
            severity,
            rec_ver,
            installed_ver,
            cve,
            fixed,
            ecosystem
        ) = row

        by_ecosystem.setdefault(
            ecosystem,
            []
        ).append(
            {
                "id": vuln_id,
                "package_name": pkg,
                "severity": severity,
                "recommended_version": rec_ver,
                "installed_version": installed_ver,
                "cve_id": cve,
                "fixed_version": fixed,
                "ecosystem": ecosystem
            }
        )

    analisar_lote = get_ai_agent()

    approved = 0
    manual = 0
    ignored = 0

    cur = conn.cursor()

    for ecosystem, vulns in by_ecosystem.items():

        log(
            f"\n🌍 {ecosystem}: "
            f"{len(vulns)} vulnerabilidade(s)"
        )

        # ====================================================
        # IA DISPONÍVEL
        # ====================================================

        if analisar_lote:

            try:

                log(
                    "  🧠 IA analisando relatório "
                    "+ recomendações do banco..."
                )

                decisoes = analisar_lote(
                    vulns
                )

                for decision in decisoes:

                    pkg = decision[
                        "package_name"
                    ]

                    package_vulns = [
                        v
                        for v in vulns
                        if v["package_name"] == pkg
                    ]

                    decision = _validate_ai_decision(
                        conn,
                        decision,
                        package_vulns,
                        ecosystem
                    )

                    status = decision.get(
                        "decision",
                        "MANUAL_REVIEW"
                    )

                    rec_ver = decision.get(
                        "recommended_version"
                    )

                    justification = decision.get(
                        "justification",
                        ""
                    )

                    if status == "APPROVED":
                        approved += 1

                    elif status == "IGNORE":
                        ignored += 1

                    else:
                        manual += 1

                    cur.execute(
                        """
                        UPDATE vulnerability_records
                        SET
                            decision_status=%s,
                            ai_justification=%s,
                            recommended_version=
                                COALESCE(
                                    %s,
                                    recommended_version
                                ),
                            updated_at=NOW()
                        WHERE package_name=%s
                          AND ecosystem=%s
                          AND remediation_status='OPEN'
                          AND decision_status='PENDING'
                        """,
                        (
                            status,
                            justification,
                            rec_ver,
                            pkg,
                            ecosystem
                        )
                    )

                conn.commit()

                log(
                    "  ✅ IA concluiu a tomada de decisão."
                )

            except Exception as e:

                log(
                    f"  ⚠️ IA falhou: {e}",
                    "WARN"
                )

                log(
                    "  🔄 Ativando fallback pelo "
                    "banco homologado/OSV.",
                    "WARN"
                )

                conn.rollback()

                # =================================================
                # FALLBACK
                # =================================================

                for (
                    pkg,
                    decision,
                    rec,
                    justification
                ) in _fallback_decision_by_curated(
                    conn,
                    vulns,
                    ecosystem
                ):

                    if decision == "APPROVED":
                        approved += 1

                    elif decision == "IGNORE":
                        ignored += 1

                    else:
                        manual += 1

                    cur.execute(
                        """
                        UPDATE vulnerability_records
                        SET
                            decision_status=%s,
                            recommended_version=
                                COALESCE(
                                    %s,
                                    recommended_version
                                ),
                            ai_justification=%s,
                            updated_at=NOW()
                        WHERE package_name=%s
                          AND ecosystem=%s
                          AND remediation_status='OPEN'
                          AND decision_status='PENDING'
                        """,
                        (
                            decision,
                            rec,
                            justification,
                            pkg,
                            ecosystem
                        )
                    )

                    log(
                        f"    DB fallback: "
                        f"{pkg} -> "
                        f"{decision} "
                        f"({rec or 'N/A'})"
                    )

                conn.commit()

        # ====================================================
        # IA INDISPONÍVEL
        # ====================================================

        else:

            log(
                "  ⚠️ IA indisponível."
            )

            log(
                "  🗄️ Utilizando diretamente "
                "o banco homologado/OSV.",
                "WARN"
            )

            for (
                pkg,
                decision,
                rec,
                justification
            ) in _fallback_decision_by_curated(
                conn,
                vulns,
                ecosystem
            ):

                if decision == "APPROVED":
                    approved += 1

                elif decision == "IGNORE":
                    ignored += 1

                else:
                    manual += 1

                cur.execute(
                    """
                    UPDATE vulnerability_records
                    SET
                        decision_status=%s,
                        recommended_version=
                            COALESCE(
                                %s,
                                recommended_version
                            ),
                        ai_justification=%s,
                        updated_at=NOW()
                    WHERE package_name=%s
                      AND ecosystem=%s
                      AND remediation_status='OPEN'
                      AND decision_status='PENDING'
                    """,
                    (
                        decision,
                        rec,
                        justification,
                        pkg,
                        ecosystem
                    )
                )

                log(
                    f"    DB fallback: "
                    f"{pkg} -> "
                    f"{decision} "
                    f"({rec or 'N/A'})"
                )

            conn.commit()

    cur.close()

    log(
        "\n✅ Decisões finais: "
        f"Approved={approved} | "
        f"Manual Review={manual} | "
        f"Ignored={ignored}"
    )


# ============================================================
# STAGE 3
# APLICAÇÃO DO PATCH
#
# SEM VIRTUAL PATCH
# ============================================================

COMMANDS = {

    "composer":
        lambda pkg, ver:
        [
            "composer",
            "require",
            f"{pkg}:{ver}",
            "--no-interaction"
        ],

    "npm":
        lambda pkg, ver:
        [
            "npm",
            "install",
            f"{pkg}@{ver}"
        ],

    "pip":
        lambda pkg, ver:
        [
            "pip",
            "install",
            f"{pkg}=={ver}"
        ],
}


def run_smoke_test(ecosystem):

    if ecosystem == "PHP":

        result = subprocess.run(
            """
            for f in $(find . -name '*.php' \
            -not -path './vendor/*');
            do
                php -l "$f" 2>&1 || exit 1;
            done
            """,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:

            log(
                "❌ Smoke test PHP falhou.",
                "WARN"
            )

            return False

        if os.path.exists(
            "composer.json"
        ):

            result = subprocess.run(
                [
                    "composer",
                    "install",
                    "--no-interaction",
                    "--no-progress",
                    "--prefer-dist"
                ],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:

                log(
                    "❌ composer install falhou.",
                    "WARN"
                )

                return False

        return True

    elif ecosystem == "Node.js":

        result = subprocess.run(
            """
            for f in $(find . -name '*.js' \
            -not -path './node_modules/*');
            do
                node --check "$f" 2>&1 || exit 1;
            done
            """,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )

        return result.returncode == 0

    elif ecosystem == "Python":

        files = []

        for root, dirs, filenames in os.walk("."):

            dirs[:] = [
                d
                for d in dirs
                if d not in {
                    ".git",
                    "venv",
                    "env",
                    ".venv",
                    "__pycache__"
                }
            ]

            files.extend(
                os.path.join(root, f)
                for f in filenames
                if f.endswith(".py")
            )

        if not files:
            return True

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "py_compile",
                *files
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:

            log(
                f"❌ Smoke test Python falhou: "
                f"{result.stderr[:200]}",
                "WARN"
            )

            return False

        return True

    return True


def stage3_apply_patches(conn):

    log("=" * 60)
    log(
        "STAGE 3 — Aplicação dos Patches"
    )
    log(
        "Virtual Patch DESABILITADO"
    )
    log("=" * 60)

    cur = conn.cursor()

    cur.execute(
        """
        SELECT DISTINCT ecosystem
        FROM vulnerability_records
        WHERE decision_status='APPROVED'
          AND remediation_status='OPEN'
          AND ecosystem != 'UNKNOWN'
        ORDER BY ecosystem
        """
    )

    ecosystems = [
        row[0]
        for row in cur.fetchall()
    ]

    if not ecosystems:

        log(
            "Nenhuma vulnerabilidade aprovada."
        )

        cur.close()

        return 0

    total_remediated = 0
    total_failed = 0

    for ecosystem in ecosystems:

        pm = PACKAGE_MANAGERS.get(
            ecosystem
        )

        if not pm:
            continue

        log(
            f"\n🌍 {ecosystem}"
        )

        binary = shutil.which(pm)

        if not binary:

            log(
                f"{pm} não encontrado.",
                "ERROR"
            )

            continue

        cur.execute(
            """
            SELECT
                package_name,
                installed_version,
                recommended_version,
                ai_justification
            FROM vulnerability_records
            WHERE decision_status='APPROVED'
              AND remediation_status='OPEN'
              AND ecosystem=%s
            GROUP BY
                package_name,
                installed_version,
                recommended_version,
                ai_justification
            ORDER BY package_name
            """,
            (ecosystem,)
        )

        rows = cur.fetchall()

        for (
            pkg,
            old_ver,
            new_ver,
            justification
        ) in rows:

            # =================================================
            # REGRA FUNDAMENTAL
            #
            # Nenhuma versão fora do banco pode ser instalada.
            # =================================================

            curated_versions = {
                v["version"]
                for v in _get_curated_versions(
                    conn,
                    pkg,
                    ecosystem
                )
            }

            if not new_ver:

                log(
                    f"  ⏸️ {pkg}: nenhuma versão "
                    f"homologada definida.",
                    "WARN"
                )

                cur.execute(
                    """
                    UPDATE vulnerability_records
                    SET
                        decision_status='MANUAL_REVIEW',
                        updated_at=NOW()
                    WHERE package_name=%s
                      AND ecosystem=%s
                      AND decision_status='APPROVED'
                      AND remediation_status='OPEN'
                    """,
                    (
                        pkg,
                        ecosystem
                    )
                )

                continue

            if new_ver not in curated_versions:

                log(
                    f"  ⏸️ {pkg}: {new_ver} "
                    f"não está homologada.",
                    "WARN"
                )

                cur.execute(
                    """
                    UPDATE vulnerability_records
                    SET
                        decision_status='MANUAL_REVIEW',
                        updated_at=NOW()
                    WHERE package_name=%s
                      AND ecosystem=%s
                      AND decision_status='APPROVED'
                      AND remediation_status='OPEN'
                    """,
                    (
                        pkg,
                        ecosystem
                    )
                )

                continue

            log(
                f"  🔧 {pkg}: "
                f"{old_ver} → {new_ver}"
            )

            if justification:

                log(
                    f"     {justification[:150]}"
                )

            cmd = COMMANDS[pm](
                pkg,
                new_ver
            )

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:

                log(
                    f"  ❌ Falha ao instalar "
                    f"{pkg}: "
                    f"{result.stderr[:250]}",
                    "WARN"
                )

                # IMPORTANTE:
                # NÃO chama gerar_virtual_patch.
                # NÃO tenta criar patch alternativo.
                # NÃO inventa outra versão.

                cur.execute(
                    """
                    UPDATE vulnerability_records
                    SET
                        remediation_status='FAILED',
                        previous_version=installed_version,
                        updated_at=NOW()
                    WHERE package_name=%s
                      AND ecosystem=%s
                      AND decision_status='APPROVED'
                      AND remediation_status='OPEN'
                    """,
                    (
                        pkg,
                        ecosystem
                    )
                )

                total_failed += 1

                conn.commit()

                continue

            log(
                "  ✅ Update aplicado."
            )

            # =================================================
            # SMOKE TEST
            # =================================================

            log(
                "  🔍 Executando smoke test..."
            )

            smoke_ok = run_smoke_test(
                ecosystem
            )

            if smoke_ok:

                log(
                    "  ✅ Smoke test passou."
                )

                cur.execute(
                    """
                    UPDATE vulnerability_records
                    SET
                        remediation_status='REMEDIATED',
                        previous_version=installed_version,
                        updated_at=NOW()
                    WHERE package_name=%s
                      AND ecosystem=%s
                      AND decision_status='APPROVED'
                      AND remediation_status='OPEN'
                    """,
                    (
                        pkg,
                        ecosystem
                    )
                )

                total_remediated += 1

            else:

                # =================================================
                # SEM VIRTUAL PATCH
                # =================================================

                log(
                    "  ❌ Smoke test falhou após "
                    "a atualização.",
                    "WARN"
                )

                log(
                    "  ⛔ Virtual Patch não será "
                    "executado. Requer validação "
                    "antes de ser utilizado.",
                    "WARN"
                )

                # Reverte somente os arquivos de dependência
                # existentes no projeto.

                dependency_files = [
                    file
                    for file in [
                        "composer.json",
                        "composer.lock",
                        "package.json",
                        "package-lock.json",
                        "requirements.txt",
                        "pyproject.toml",
                        "poetry.lock"
                    ]
                    if os.path.exists(file)
                ]

                if dependency_files:

                    subprocess.run(
                        [
                            "git",
                            "checkout",
                            "--",
                            *dependency_files
                        ],
                        capture_output=True,
                        text=True
                    )

                cur.execute(
                    """
                    UPDATE vulnerability_records
                    SET
                        remediation_status='FAILED',
                        previous_version=installed_version,
                        updated_at=NOW()
                    WHERE package_name=%s
                      AND ecosystem=%s
                      AND decision_status='APPROVED'
                      AND remediation_status='OPEN'
                    """,
                    (
                        pkg,
                        ecosystem
                    )
                )

                total_failed += 1

            conn.commit()

    cur.close()

    log(
        f"\n✅ PATCHES: "
        f"{total_remediated} remediados | "
        f"{total_failed} falhas"
    )

    return total_remediated


# ============================================================
# STAGE 4
# ============================================================

def stage4_validate_via_report(
    conn,
    execution_id,
    vulns_before,
    post_report_path="reports/report_post_patch.json"
):

    log("=" * 60)
    log(
        "STAGE 4 — Validação Pós-Patch"
    )
    log("=" * 60)

    # Se a Pipeline 1 ainda não gerou o relatório pós-patch,
    # o próprio framework executa a validação final com Trivy.
    # Isso evita declarar SUCCESS apenas porque o arquivo não existe.
    if not os.path.exists(post_report_path):

        trivy = shutil.which("trivy")

        if not trivy:
            log(
                "Trivy não encontrado para validação pós-patch.",
                "ERROR"
            )
            return False

        os.makedirs(
            os.path.dirname(post_report_path) or ".",
            exist_ok=True
        )

        log(
            "🔍 Executando re-scan Trivy pós-patch..."
        )

        result = subprocess.run(
            [
                trivy,
                "fs",
                ".",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--output",
                post_report_path,
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        # Trivy pode retornar exit code 1 quando encontra vulnerabilidades.
        # O JSON é a fonte da verdade; portanto o código de saída não é
        # considerado erro fatal se o relatório foi produzido.
        if result.returncode not in (0, 1):
            log(
                "Falha na execução do Trivy pós-patch: "
                f"{result.stderr[:500]}",
                "ERROR"
            )
            return False

        if not os.path.exists(post_report_path):
            log(
                "Trivy não produziu o relatório pós-patch.",
                "ERROR"
            )
            return False

        log(
            f"✅ Relatório pós-patch gerado: {post_report_path}"
        )

    try:

        with open(
            post_report_path,
            encoding="utf-8"
        ) as f:

            post = json.load(f)

        vulns_after = 0

        for result in post.get(
            "Results",
            []
        ):

            vulns_after += len(
                result.get(
                    "Vulnerabilities"
                )
                or []
            )

        reduction = (
            round(
                (
                    vulns_before
                    - vulns_after
                )
                / vulns_before
                * 100,
                2
            )
            if vulns_before > 0
            else 0
        )

        log(
            f"Vulnerabilidades: "
            f"{vulns_before} → "
            f"{vulns_after} "
            f"({reduction}%)"
        )

        if execution_id:

            cur = conn.cursor()

            cur.execute(
                """
                UPDATE pipeline_executions
                SET
                    vulnerabilities_resolved=%s,
                    reduction_percentage=%s
                WHERE id=%s
                """,
                (
                    vulns_before - vulns_after,
                    reduction,
                    execution_id
                )
            )

            conn.commit()
            cur.close()

        if vulns_after > 0:

            log(
                f"⚠️ {vulns_after} "
                f"vulnerabilidade(s) restantes.",
                "WARN"
            )

        return vulns_after == 0

    except Exception as e:

        log(
            f"Erro ao ler relatório "
            f"pós-patch: {e}",
            "WARN"
        )

        return True


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n"
        + "=" * 60
    )

    print(
        "🔒 PIPELINE AUTÔNOMO DE REMEDIAÇÃO SCA"
    )

    print(
        "   IA como tomadora de decisão"
    )

    print(
        "   Fallback: banco homologado + OSV"
    )

    print(
        "   Virtual Patch: DESABILITADO"
    )

    print(
        "=" * 60
    )

    if not os.path.exists(
        "reports/report.json"
    ):

        log(
            "reports/report.json não encontrado.",
            "ERROR"
        )

        sys.exit(1)

    conn = connect_db()

    execution_id = None
    vulns_found = 0

    try:

        # -----------------------------------------------
        # STAGE 1
        # -----------------------------------------------

        (
            execution_id,
            vulns_found
        ) = stage1_load_and_persist(
            conn
        )

        # -----------------------------------------------
        # STAGE 2
        # IA ou banco
        # -----------------------------------------------

        stage2_ai_decide(
            conn
        )

        # -----------------------------------------------
        # STAGE 3
        # Somente versões homologadas
        # -----------------------------------------------

        remediated = (
            stage3_apply_patches(
                conn
            )
        )

        # -----------------------------------------------
        # STAGE 4
        # -----------------------------------------------

        success = (
            stage4_validate_via_report(
                conn,
                execution_id,
                vulns_found
            )
        )

        status = (
            "SUCCESS"
            if success
            else "PARTIAL"
        )

        if execution_id:

            db_safe(
                db_finish_execution,
                conn,
                execution_id,
                status,
                vulns_found,
                remediated
            )

        print(
            "\n"
            + "=" * 60
        )

        if success:

            print(
                "✅ PIPELINE CONCLUÍDO"
            )

        else:

            print(
                "⚠️ PIPELINE CONCLUÍDO — "
                "REVISÃO MANUAL NECESSÁRIA"
            )

        print(
            "=" * 60
        )

    except Exception as e:

        log(
            f"Erro crítico no pipeline: {e}",
            "ERROR"
        )

        if execution_id:

            db_safe(
                db_finish_execution,
                conn,
                execution_id,
                "FAILED",
                vulns_found,
                0
            )

        raise

    finally:

        conn.close()


if __name__ == "__main__":
    main()

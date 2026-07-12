-- ==========================================
-- Schema Principal - Framework de Remediação
-- Banco: Supabase (PostgreSQL 16)
-- ==========================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ------------------------------------------
-- Execuções do pipeline (uma por workflow run)
-- Histórico permanente: nunca deletado
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS pipeline_executions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_name         TEXT NOT NULL,
    workflow_run_id         TEXT,
    started_at              TIMESTAMP DEFAULT NOW(),
    finished_at             TIMESTAMP,
    status                  TEXT DEFAULT 'RUNNING',   -- RUNNING | SUCCESS | FAILED
    vulnerabilities_found   INTEGER DEFAULT 0,
    vulnerabilities_resolved INTEGER DEFAULT 0,
    reduction_percentage    NUMERIC(5,2) DEFAULT 0
);

-- ------------------------------------------
-- Vulnerabilidades detectadas por execução
-- Cada run insere novos registros — histórico preservado
-- previous_version permite rollback
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerability_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id        UUID REFERENCES pipeline_executions(id),
    cve_id              TEXT,
    package_name        TEXT,
    severity            TEXT,
    installed_version   TEXT,
    previous_version    TEXT,                          -- salvo antes de remediar (rollback)
    fixed_version       TEXT,
    recommended_version TEXT,
    osv_reference       TEXT,                          -- GHSA-xxx-yyy-zzz ou NULL
    source_db           TEXT DEFAULT 'UNKNOWN',        -- CURATED_DB | OSV_API | NONE | UNKNOWN
    decision_status     TEXT DEFAULT 'PENDING',        -- PENDING | APPROVED | MANUAL_REVIEW | IGNORE
    remediation_status  TEXT DEFAULT 'OPEN',           -- OPEN | REMEDIATED | FAILED | ROLLED_BACK
    ai_justification    TEXT,
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);

-- ------------------------------------------
-- Versões homologadas (banco curado pela equipe)
-- Consultado ANTES da OSV API
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS homologated_versions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_name TEXT NOT NULL,
    ecosystem    TEXT NOT NULL,                        -- PHP | Node.js | Python
    safe_version TEXT NOT NULL,
    approved_by  TEXT,
    approved_at  TIMESTAMP DEFAULT NOW(),
    notes        TEXT,
    UNIQUE(package_name, ecosystem, safe_version)
);

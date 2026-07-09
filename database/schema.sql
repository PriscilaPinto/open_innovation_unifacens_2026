CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS pipeline_executions (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    repository_name TEXT NOT NULL,

    workflow_run_id TEXT,

    started_at TIMESTAMP DEFAULT NOW(),

    finished_at TIMESTAMP,

    status TEXT,

    vulnerabilities_found INTEGER,

    vulnerabilities_resolved INTEGER,

    reduction_percentage NUMERIC(5,2)
);

CREATE TABLE IF NOT EXISTS vulnerability_records (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    execution_id UUID REFERENCES pipeline_executions(id),

    cve_id TEXT,

    package_name TEXT,

    severity TEXT,

    installed_version TEXT,

    fixed_version TEXT,

    recommended_version TEXT,

    osv_reference TEXT,

    decision_status TEXT DEFAULT 'PENDING',

    remediation_status TEXT DEFAULT 'OPEN',

    ai_justification TEXT,

    created_at TIMESTAMP DEFAULT NOW(),

    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pull_requests (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    execution_id UUID REFERENCES pipeline_executions(id),

    pr_number INTEGER,

    pr_url TEXT,

    approval_status TEXT,

    created_at TIMESTAMP DEFAULT NOW()
);

-- ==========================================
-- TABELA DE VERSÕES HOMOLOGADAS (OPCIONAL)
-- ==========================================
-- Permite que a equipe cure manualmente versões seguras
-- que já foram testadas em produção
-- ==========================================

CREATE TABLE IF NOT EXISTS homologated_versions (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    package_name TEXT NOT NULL,

    ecosystem TEXT NOT NULL,  -- 'PHP', 'Node.js', 'Python'

    safe_version TEXT NOT NULL,

    approved_by TEXT,

    approved_at TIMESTAMP DEFAULT NOW(),

    notes TEXT,

    UNIQUE(package_name, ecosystem, safe_version)
);

CREATE INDEX IF NOT EXISTS idx_vulnerability_records_execution_id
    ON vulnerability_records(execution_id);

CREATE INDEX IF NOT EXISTS idx_vulnerability_records_status
    ON vulnerability_records(decision_status, remediation_status);

CREATE INDEX IF NOT EXISTS idx_vulnerability_records_package_open
    ON vulnerability_records(package_name, remediation_status);

-- Exemplo de dados pré-populados (use seed_homologated_versions.sql para carga completa)
-- INSERT INTO homologated_versions ... (ver database/seed_homologated_versions.sql)

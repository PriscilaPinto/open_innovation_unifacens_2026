CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE pipeline_executions (

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

CREATE TABLE vulnerability_records (

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

CREATE TABLE pull_requests (

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

CREATE TABLE homologated_versions (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    package_name TEXT NOT NULL,

    ecosystem TEXT NOT NULL,  -- 'PHP', 'Node.js', 'Python'

    safe_version TEXT NOT NULL,

    approved_by TEXT,

    approved_at TIMESTAMP DEFAULT NOW(),

    notes TEXT,

    UNIQUE(package_name, ecosystem, safe_version)
);

-- Exemplo de dados pré-populados
INSERT INTO homologated_versions (package_name, ecosystem, safe_version, approved_by, notes) VALUES
('guzzlehttp/guzzle', 'PHP', '6.5.8', 'Security Team', 'Testado em produção, sem breaking changes'),
('guzzlehttp/guzzle', 'PHP', '7.4.5', 'Security Team', 'Versão mais recente, requer PHP 7.2+'),
('monolog/monolog', 'PHP', '2.9.2', 'Security Team', 'Última versão estável');

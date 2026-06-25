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

    remediation_status TEXT,

    ai_justification TEXT
);

CREATE TABLE pull_requests (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    execution_id UUID REFERENCES pipeline_executions(id),

    pr_number INTEGER,

    pr_url TEXT,

    approval_status TEXT,

    created_at TIMESTAMP DEFAULT NOW()
);
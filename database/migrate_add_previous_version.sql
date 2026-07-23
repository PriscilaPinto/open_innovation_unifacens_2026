-- Migrations do Framework de Remediação de Vulnerabilidades
-- Arquivo unificado: todas as migrations em um só lugar
-- Seguro para rodar múltiplas vezes (IF NOT EXISTS)
-- Data: 2026-07-12

-- ============================================================
-- Migration 1: Adicionar coluna previous_version
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vulnerability_records'
          AND column_name = 'previous_version'
    ) THEN
        ALTER TABLE vulnerability_records
        ADD COLUMN previous_version TEXT;
    END IF;
END $$;

-- Garante que o default de decision_status é PENDING
ALTER TABLE vulnerability_records
    ALTER COLUMN decision_status SET DEFAULT 'PENDING';

-- Corrige registros existentes sem decision_status definido
UPDATE vulnerability_records
SET decision_status = 'PENDING'
WHERE decision_status IS NULL;

-- ============================================================
-- Migration 2: Adicionar coluna source_db para rastreamento
-- Requisito 3: Rastreabilidade (CURATED_DB vs OSV_API)
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vulnerability_records'
          AND column_name = 'source_db'
    ) THEN
        ALTER TABLE vulnerability_records
        ADD COLUMN source_db TEXT DEFAULT 'UNKNOWN';
    END IF;
END $$;

-- Comentário explicativo
COMMENT ON COLUMN vulnerability_records.source_db IS 
  'Origem dos dados: CURATED_DB (homologated_versions), OSV_API (Google), NONE (sem recomendação), UNKNOWN (não definido)';

-- ============================================================
-- Migration 3: Adicionar coluna ecosystem para multi-linguagem
-- Rastreia qual ecossistema (PHP, Node.js, Python) cada vuln pertence
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vulnerability_records'
          AND column_name = 'ecosystem'
    ) THEN
        ALTER TABLE vulnerability_records
        ADD COLUMN ecosystem TEXT DEFAULT 'UNKNOWN';
    END IF;
END $$;

-- Comentário explicativo
COMMENT ON COLUMN vulnerability_records.ecosystem IS 
  'Ecossistema: PHP (Packagist), Node.js (npm), Python (PyPI), UNKNOWN';

-- ============================================================
-- Migration 4: Adicionar coluna homolog_status para o security gate
-- A pipeline 1 (ai-agent-security) define status (SUCCESS/FAILED)
-- A pipeline 2 (homolog-security-gate) define homolog_status
-- Isso evita conflito: uma execução tem dois momentos de validação
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'pipeline_executions'
          AND column_name = 'homolog_status'
    ) THEN
        ALTER TABLE pipeline_executions
        ADD COLUMN homolog_status TEXT DEFAULT 'PENDING';  -- PENDING | VALIDATED | REJECTED
    END IF;
END $$;

COMMENT ON COLUMN pipeline_executions.homolog_status IS 
  'Status da validação em homolog: PENDING (aguardando), VALIDATED (aprovado), REJECTED (reprovado)';

-- ============================================================
-- Migration 5: Virtual Patch — colunas para armazenar mitigação
-- Quando o update quebra compatibilidade, a IA gera um patch
-- virtual que mitiga a CVE sem alterar a versão da dependência
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vulnerability_records'
          AND column_name = 'virtual_patch_path'
    ) THEN
        ALTER TABLE vulnerability_records
        ADD COLUMN virtual_patch_path TEXT;          -- Caminho do arquivo de patch gerado
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vulnerability_records'
          AND column_name = 'virtual_patch_data'
    ) THEN
        ALTER TABLE vulnerability_records
        ADD COLUMN virtual_patch_data TEXT;          -- Código do patch gerado pela IA
    END IF;
END $$;

COMMENT ON COLUMN vulnerability_records.virtual_patch_path IS 
  'Caminho do arquivo de virtual patch gerado (ex: virtual_patches/CVE-2022-29248.php)';
COMMENT ON COLUMN vulnerability_records.virtual_patch_data IS 
  'Código de mitigação gerado pela IA quando o update quebra compatibilidade';

-- Atualiza o comment do remediation_status para incluir VIRTUAL_PATCH
COMMENT ON COLUMN vulnerability_records.remediation_status IS 
  'OPEN | REMEDIATED | FAILED | ROLLED_BACK | VIRTUAL_PATCH';

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

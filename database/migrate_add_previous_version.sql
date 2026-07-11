-- Migration: adiciona coluna previous_version se não existir
-- Garante decision_status default PENDING
-- Seguro para rodar múltiplas vezes
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

-- Migration: adiciona coluna previous_version se não existir
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

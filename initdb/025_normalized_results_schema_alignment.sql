-- Align legacy normalized_results tables with the current SQLAlchemy model.
-- Existing legacy columns are preserved for historical compatibility.
ALTER TABLE normalized_results
    ADD COLUMN IF NOT EXISTS open_port_id INT REFERENCES open_ports(id) ON DELETE SET NULL;

ALTER TABLE normalized_results
    ADD COLUMN IF NOT EXISTS normalized_output JSONB;

-- A clean 018 schema already has normalized_output and has no normalized_data.
-- Only backfill when upgrading a legacy table that actually has that column.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'normalized_results'
          AND column_name = 'normalized_data'
    ) THEN
        EXECUTE 'UPDATE normalized_results
                 SET normalized_output = normalized_data
                 WHERE normalized_output IS NULL
                   AND normalized_data IS NOT NULL';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_normalized_results_open_port_id
    ON normalized_results(open_port_id);

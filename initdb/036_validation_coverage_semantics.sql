-- Make candidate validation coverage explicit. Existing rows are deliberately
-- left NOT_EVALUATED; no historical ToolResult is replayed or backfilled.
ALTER TABLE vulnerability_candidates
  ADD COLUMN IF NOT EXISTS validation_coverage VARCHAR(24) NOT NULL DEFAULT 'NOT_EVALUATED';

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'vulnerability_candidates'::regclass
      AND conname = 'vulnerability_candidates_validation_coverage_values'
  ) THEN
    ALTER TABLE vulnerability_candidates
      ADD CONSTRAINT vulnerability_candidates_validation_coverage_values
      CHECK (validation_coverage IN ('COVERED', 'NOT_COVERED', 'UNKNOWN', 'NOT_EVALUATED'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_vulnerability_candidates_validation_coverage
  ON vulnerability_candidates(target_id, validation_coverage, status);

-- Rollback: remove only the additive coverage column, its check and index after
-- stopping upgraded application processes. Do not alter historical candidate rows.

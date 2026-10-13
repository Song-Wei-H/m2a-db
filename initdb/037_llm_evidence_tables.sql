-- Add only the two ORM-mapped tables confirmed absent by live PostgreSQL
-- verification. Do not infer foreign keys or secondary indexes from column
-- names; app/models.py declares neither for these models.
-- This migration is forward-only and is executed in a psql -1 transaction.

DO $$
DECLARE
  existing_name text;
BEGIN
  -- Migration 037 requires the finalized Migration 036 coverage schema.
  IF to_regclass('public.vulnerability_candidates') IS NULL THEN
    RAISE EXCEPTION 'Migration 037 requires public.vulnerability_candidates from migration 035';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid = 'public.vulnerability_candidates'::regclass
      AND attname = 'validation_coverage'
      AND atttypid = 'character varying'::regtype
      AND atttypmod = 28 -- varchar(24) includes PostgreSQL's 4-byte header
      AND attnotnull
      AND NOT attisdropped
  ) THEN
    RAISE EXCEPTION 'Migration 037 requires migration 036 validation_coverage varchar(24) NOT NULL';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.vulnerability_candidates'::regclass
      AND conname = 'vulnerability_candidates_validation_coverage_values'
      AND contype = 'c'
      AND convalidated
  ) THEN
    RAISE EXCEPTION 'Migration 037 requires the validated migration 036 coverage constraint';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'vulnerability_candidates'
      AND indexname = 'idx_vulnerability_candidates_validation_coverage'
  ) THEN
    RAISE EXCEPTION 'Migration 037 requires the migration 036 validation coverage index';
  END IF;

  -- Fail closed for either a complete object or a partially-created relation.
  FOREACH existing_name IN ARRAY ARRAY['evidence_confidence', 'llm_recommendations'] LOOP
    IF EXISTS (
      SELECT 1 FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname = existing_name
    ) THEN
      RAISE EXCEPTION 'Migration 037 refuses pre-existing or partial public.%', existing_name;
    END IF;
  END LOOP;
END
$$;

CREATE TABLE public.evidence_confidence (
  id SERIAL PRIMARY KEY,
  target_id INTEGER,
  open_port_id INTEGER,
  decision_score_id INTEGER,
  tool_result_id INTEGER,
  tool_name VARCHAR(100),
  evidence_type VARCHAR(100),
  confidence_score DOUBLE PRECISION,
  confidence_reason TEXT,
  supporting_evidence JSONB,
  contradictory_evidence JSONB,
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE public.llm_recommendations (
  id SERIAL PRIMARY KEY,
  target_id INTEGER,
  decision_score_id INTEGER,
  evidence_confidence_id INTEGER,
  recommended_action VARCHAR(50),
  recommended_tool VARCHAR(100),
  confidence DOUBLE PRECISION,
  reasoning TEXT,
  raw_response JSONB,
  approved BOOLEAN NOT NULL DEFAULT false,
  validator_status VARCHAR(50),
  validator_reason TEXT,
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now()
);

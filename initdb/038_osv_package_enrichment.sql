-- Forward-only schema for exact package/version OSV lookups.
-- This file is reviewed/tested only; it is not applied by this change.
-- Apply in a transaction after migrations 018/025 have created normalized_results.

DO $$
DECLARE
  existing_name text;
BEGIN
  IF to_regclass('public.normalized_results') IS NULL THEN
    RAISE EXCEPTION 'Migration 038 requires public.normalized_results';
  END IF;

  FOREACH existing_name IN ARRAY ARRAY['osv_package_query_cache', 'osv_normalized_evidence'] LOOP
    IF EXISTS (
      SELECT 1 FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname = existing_name
    ) THEN
      RAISE EXCEPTION 'Migration 038 refuses pre-existing or partial public.%', existing_name;
    END IF;
  END LOOP;
END
$$;

CREATE TABLE public.osv_package_query_cache (
  id BIGSERIAL PRIMARY KEY,
  cache_key VARCHAR(64) NOT NULL UNIQUE,
  ecosystem VARCHAR(80) NOT NULL,
  package_name VARCHAR(500) NOT NULL,
  package_version VARCHAR(255) NOT NULL,
  status VARCHAR(24) NOT NULL CHECK (status IN ('pending', 'complete', 'no_match', 'partial', 'failed')),
  source VARCHAR(32) NOT NULL DEFAULT 'OSV',
  retrieved_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  retry_after TIMESTAMPTZ,
  response_sha256 VARCHAR(64) CHECK (response_sha256 IS NULL OR response_sha256 ~ '^[0-9a-f]{64}$'),
  last_attempt_sha256 VARCHAR(64) CHECK (last_attempt_sha256 IS NULL OR last_attempt_sha256 ~ '^[0-9a-f]{64}$'),
  response_summary JSONB,
  match_confidence DOUBLE PRECISION CHECK (match_confidence IS NULL OR (match_confidence >= 0 AND match_confidence <= 1)),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  error_code VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_osv_package_query_cache_status_retry
  ON public.osv_package_query_cache(status, retry_after);
CREATE INDEX idx_osv_package_query_cache_expiry
  ON public.osv_package_query_cache(expires_at);

CREATE TABLE public.osv_normalized_evidence (
  id BIGSERIAL PRIMARY KEY,
  normalized_result_id INTEGER NOT NULL REFERENCES public.normalized_results(id) ON DELETE CASCADE,
  identity_key VARCHAR(64) NOT NULL,
  cache_id BIGINT REFERENCES public.osv_package_query_cache(id) ON DELETE SET NULL,
  package_identity JSONB,
  status VARCHAR(24) NOT NULL CHECK (status IN ('pending', 'complete', 'no_match', 'partial', 'unsupported', 'failed', 'stale', 'disabled')),
  source VARCHAR(32) NOT NULL DEFAULT 'OSV',
  retrieved_at TIMESTAMPTZ,
  response_sha256 VARCHAR(64) CHECK (response_sha256 IS NULL OR response_sha256 ~ '^[0-9a-f]{64}$'),
  last_attempt_sha256 VARCHAR(64) CHECK (last_attempt_sha256 IS NULL OR last_attempt_sha256 ~ '^[0-9a-f]{64}$'),
  match_confidence DOUBLE PRECISION CHECK (match_confidence IS NULL OR (match_confidence >= 0 AND match_confidence <= 1)),
  evidence_ref VARCHAR(255) NOT NULL,
  result_summary JSONB,
  error_code VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_osv_normalized_evidence_identity UNIQUE (normalized_result_id, identity_key)
);

CREATE INDEX idx_osv_normalized_evidence_normalized_result
  ON public.osv_normalized_evidence(normalized_result_id);
CREATE INDEX idx_osv_normalized_evidence_cache_id
  ON public.osv_normalized_evidence(cache_id);

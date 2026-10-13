-- Additive/idempotent. Historical rows stay NULL, never fabricated/backfilled.
ALTER TABLE decision_proposals ADD COLUMN IF NOT EXISTS decision_score_id INTEGER REFERENCES decision_scores(id);
ALTER TABLE decision_proposals ADD COLUMN IF NOT EXISTS raw_proposal JSONB;
ALTER TABLE decision_proposals ADD COLUMN IF NOT EXISTS evidence_refs JSONB;
ALTER TABLE decision_proposals ADD COLUMN IF NOT EXISTS input_hash VARCHAR(64);
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS execution_request JSONB;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS execution_request_hash VARCHAR(64);
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS execution_audit JSONB;
ALTER TABLE tool_results ADD COLUMN IF NOT EXISTS execution_receipt JSONB;
ALTER TABLE tool_results ADD COLUMN IF NOT EXISTS output_hash VARCHAR(64);
CREATE TABLE IF NOT EXISTS authorization_decisions (
    id SERIAL PRIMARY KEY,
    proposal_id INTEGER NOT NULL REFERENCES decision_proposals(id),
    authorization_id INTEGER UNIQUE REFERENCES execution_authorizations(id),
    outcome VARCHAR(16) NOT NULL CHECK (outcome IN ('ALLOW','DENY','PENDING')),
    reason TEXT NOT NULL, policy_source VARCHAR(100) NOT NULL,
    contract_snapshot JSONB NOT NULL, record_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CHECK ((outcome = 'ALLOW') = (authorization_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_authorization_decisions_proposal ON authorization_decisions(proposal_id);
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint c
        WHERE c.conrelid = 'tool_results'::regclass
          AND c.contype = 'f' AND c.confrelid = 'tool_tasks'::regclass
          AND c.conkey = ARRAY[(SELECT attnum FROM pg_attribute
                                WHERE attrelid = 'tool_results'::regclass
                                  AND attname = 'tool_task_id')]::smallint[]
    ) THEN
        ALTER TABLE tool_results ADD CONSTRAINT tool_results_tool_task_trace_fk
            FOREIGN KEY (tool_task_id) REFERENCES tool_tasks(id) NOT VALID;
    END IF;
END $$;
-- NOT VALID preserves pre-existing orphans but enforces new references.
-- Validate explicitly only after a read-only orphan inventory; never delete rows.
CREATE OR REPLACE FUNCTION protect_execution_trace() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'authorization_decisions' THEN
        RAISE EXCEPTION 'authorization evaluations are append-only';
    ELSIF TG_TABLE_NAME = 'decision_proposals' AND (to_jsonb(OLD)->>'input_hash') IS NOT NULL THEN
        IF TG_OP = 'DELETE' OR (to_jsonb(NEW) - 'status') IS DISTINCT FROM (to_jsonb(OLD) - 'status') THEN
            RAISE EXCEPTION 'proposal inputs are immutable';
        END IF;
    ELSIF TG_TABLE_NAME = 'tool_results' AND (to_jsonb(OLD)->>'output_hash') IS NOT NULL THEN
        IF TG_OP = 'DELETE' OR to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
            RAISE EXCEPTION 'traced results are immutable';
        END IF;
    ELSIF TG_TABLE_NAME = 'tool_tasks' AND (to_jsonb(OLD)->>'execution_request_hash') IS NOT NULL THEN
        IF TG_OP = 'DELETE' OR NEW.execution_request IS DISTINCT FROM OLD.execution_request
           OR NEW.execution_request_hash IS DISTINCT FROM OLD.execution_request_hash
           OR NEW.execution_authorization_id IS DISTINCT FROM OLD.execution_authorization_id
           OR NEW.target_id IS DISTINCT FROM OLD.target_id OR NEW.action_id IS DISTINCT FROM OLD.action_id THEN
            RAISE EXCEPTION 'execution request identity is immutable';
        END IF;
    ELSIF TG_TABLE_NAME = 'execution_authorizations' AND EXISTS (
        SELECT 1 FROM authorization_decisions WHERE authorization_id = OLD.id
    ) THEN
        IF TG_OP = 'DELETE' OR (to_jsonb(NEW) - 'consumed_count') IS DISTINCT FROM (to_jsonb(OLD) - 'consumed_count') THEN
            RAISE EXCEPTION 'evaluated authorization is immutable except consumption';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
DO $$ DECLARE tab TEXT; BEGIN
    FOREACH tab IN ARRAY ARRAY['authorization_decisions','decision_proposals','tool_results','tool_tasks','execution_authorizations'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = tab::regclass AND tgname = 'protect_execution_trace_trigger') THEN
            EXECUTE format('CREATE TRIGGER protect_execution_trace_trigger BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION protect_execution_trace()', tab);
        END IF;
    END LOOP;
END $$;
-- Rollback: stop upgraded application processes, restore previous code, retain
-- these additive columns/table as evidence. Do not DROP archived trace records.

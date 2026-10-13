-- M2A cumulative engagement authorization ceiling. Existing assessments use
-- a least-privilege depth of 1 and are explicitly marked as legacy defaults.
ALTER TABLE targets
    ADD COLUMN IF NOT EXISTS authorization_depth SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS authorization_policy_version VARCHAR(50) NOT NULL DEFAULT 'legacy-safe-default',
    ADD COLUMN IF NOT EXISTS authorization_effective_from TIMESTAMP,
    ADD COLUMN IF NOT EXISTS authorization_expires_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS authorization_configured_by VARCHAR(100) NOT NULL DEFAULT 'legacy-record';

UPDATE targets
SET authorization_effective_from = COALESCE(authorization_effective_from, created_at, NOW())
WHERE authorization_effective_from IS NULL;

ALTER TABLE targets
    ALTER COLUMN authorization_effective_from SET DEFAULT NOW(),
    ALTER COLUMN authorization_effective_from SET NOT NULL;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'targets'::regclass AND conname = 'targets_authorization_depth_range'
    ) THEN
        ALTER TABLE targets ADD CONSTRAINT targets_authorization_depth_range
            CHECK (authorization_depth BETWEEN 1 AND 7);
    END IF;
END $$;

-- No tool capability is added by this migration. Executable requirements are
-- maintained in app/action_contracts.py and remain separate from the ceiling.

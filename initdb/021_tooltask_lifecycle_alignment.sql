-- Idempotent ToolTask lifecycle/schema alignment.
-- Keeps ORM nullability in sync with the bootstrap schema and older migrations.

ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS tool_run VARCHAR(100);

ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending';
UPDATE tool_tasks SET status = 'pending' WHERE status IS NULL;
ALTER TABLE tool_tasks ALTER COLUMN status SET DEFAULT 'pending';
ALTER TABLE tool_tasks ALTER COLUMN status SET NOT NULL;

ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approval_status VARCHAR(50) DEFAULT 'not_required';
ALTER TABLE tool_tasks ALTER COLUMN approval_status TYPE VARCHAR(50);
UPDATE tool_tasks SET approval_status = 'not_required' WHERE approval_status IS NULL;
ALTER TABLE tool_tasks ALTER COLUMN approval_status SET DEFAULT 'not_required';
ALTER TABLE tool_tasks ALTER COLUMN approval_status SET NOT NULL;

ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approval_required BOOLEAN DEFAULT FALSE;
UPDATE tool_tasks SET approval_required = FALSE WHERE approval_required IS NULL;
ALTER TABLE tool_tasks ALTER COLUMN approval_required SET DEFAULT FALSE;
ALTER TABLE tool_tasks ALTER COLUMN approval_required SET NOT NULL;

ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approval_reason TEXT;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS reject_reason TEXT;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approved_by VARCHAR(255);

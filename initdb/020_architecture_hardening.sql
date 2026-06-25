ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approval_reason TEXT;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS reject_reason TEXT;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approved_by VARCHAR(255);

-- Duplicate protection rollout is intentionally audit-first.
-- Before creating idx_tool_tasks_active_unique in production, run:
--   initdb/duplicate_audit.sql
-- If audit returns rows, run/review:
--   initdb/dedupe.sql
-- Then create the unique index manually or through a later deployment migration.
-- Keeping this migration column-only makes it idempotent and avoids failing
-- existing deployments that already contain duplicate active ToolTasks.

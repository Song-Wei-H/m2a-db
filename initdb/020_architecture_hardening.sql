ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approval_reason TEXT;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS reject_reason TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_tasks_active_unique
  ON tool_tasks(target_id, COALESCE(open_port_id, -1), tool_name)
  WHERE status IN ('pending', 'running', 'completed');

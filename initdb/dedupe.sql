-- Conservative dedupe helper for active duplicate ToolTasks.
-- Review duplicate_audit.sql output before running this in production.
-- Keeps the oldest row for each target/open_port/tool/status group and marks
-- later duplicates as rejected with reject_reason='duplicate_active_tool_task'.

WITH ranked AS (
  SELECT
    id,
    ROW_NUMBER() OVER (
      PARTITION BY target_id, COALESCE(open_port_id, -1), tool_name, status
      ORDER BY id
    ) AS rn
  FROM tool_tasks
  WHERE status IN ('pending', 'running', 'completed')
)
UPDATE tool_tasks
SET
  status = 'rejected',
  reject_reason = COALESCE(reject_reason, 'duplicate_active_tool_task')
WHERE id IN (
  SELECT id
  FROM ranked
  WHERE rn > 1
);

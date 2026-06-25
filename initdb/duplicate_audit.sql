-- Audit active duplicate ToolTasks before enabling a DB-level unique index.
-- If this query returns rows, review and run initdb/dedupe.sql before adding
-- idx_tool_tasks_active_unique.

SELECT
  target_id,
  COALESCE(open_port_id, -1) AS open_port_key,
  tool_name,
  status,
  COUNT(*) AS duplicate_count,
  ARRAY_AGG(id ORDER BY id) AS tool_task_ids
FROM tool_tasks
WHERE status IN ('pending', 'running', 'completed')
GROUP BY target_id, COALESCE(open_port_id, -1), tool_name, status
HAVING COUNT(*) > 1
ORDER BY duplicate_count DESC, target_id, open_port_key, tool_name, status;

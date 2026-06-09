ALTER TABLE tool_results ADD COLUMN IF NOT EXISTS tool_task_id INT REFERENCES tool_tasks(id);
CREATE INDEX IF NOT EXISTS idx_tool_results_tool_task_id ON tool_results(tool_task_id);

-- Preserve the human decision rationale separately from the system reason
-- that caused a task to require approval.
ALTER TABLE tool_tasks
    ADD COLUMN IF NOT EXISTS approval_decision_reason TEXT;

ALTER TABLE tool_tasks
    ADD COLUMN IF NOT EXISTS proposal_reason TEXT;

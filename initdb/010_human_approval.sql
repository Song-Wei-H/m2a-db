-- Migration: Add approval columns to tool_tasks
-- Only add if not exists to avoid duplicate errors
ALTER TABLE tool_tasks
    ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'not_required';

ALTER TABLE tool_tasks
    ADD COLUMN IF NOT EXISTS approval_required BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE tool_tasks
    ADD COLUMN IF NOT EXISTS approval_reason TEXT;

-- Add columns for auto loop tracking
ALTER TABLE targets ADD COLUMN IF NOT EXISTS current_round INT DEFAULT 1;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS max_round INT DEFAULT 5;

-- Add table to track stop reasons
CREATE TABLE IF NOT EXISTS auto_loop_decisions (
    id SERIAL PRIMARY KEY,
    target_id INT NOT NULL REFERENCES targets(id),
    round_number INT NOT NULL,
    stop_reason VARCHAR(50),
    next_tool VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auto_loop_decisions_target_id ON auto_loop_decisions(target_id);
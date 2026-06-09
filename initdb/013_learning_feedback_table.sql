CREATE TABLE IF NOT EXISTS learning_feedback (
    id SERIAL PRIMARY KEY,
    decision_id INT,
    tool_result_id INT,
    tool_name VARCHAR(100) NOT NULL,
    service VARCHAR(50),
    evidence_type VARCHAR(50),
    recommended_action VARCHAR(50),
    success BOOLEAN,
    learning_score NUMERIC(3,1) NOT NULL,
    reason TEXT,
    feedback TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_learning_feedback_decision_id ON learning_feedback(decision_id);
CREATE INDEX IF NOT EXISTS idx_learning_feedback_tool_name ON learning_feedback(tool_name);
CREATE INDEX IF NOT EXISTS idx_learning_feedback_created_at ON learning_feedback(created_at);
CREATE INDEX IF NOT EXISTS idx_learning_feedback_tool_result_id ON learning_feedback(tool_result_id);

-- For DBs created before the learning feedback table was added
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS decision_id INT;
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS tool_result_id INT;
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS tool_name VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS service VARCHAR(50);
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS evidence_type VARCHAR(50);
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS recommended_action VARCHAR(50);
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS success BOOLEAN;
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS learning_score NUMERIC(3,1) NOT NULL DEFAULT 0.0;
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE learning_feedback ADD COLUMN IF NOT EXISTS feedback TEXT;
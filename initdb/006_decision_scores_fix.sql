-- Ensure decision_scores / tool_tasks exist without dropping dependent tables.
CREATE TABLE IF NOT EXISTS decision_scores (
  id SERIAL PRIMARY KEY,
  target_id INT NOT NULL REFERENCES targets(id),
  open_port_id INT REFERENCES open_ports(id),
  risk_score FLOAT NOT NULL,
  next_action VARCHAR(50) NOT NULL,
  next_tool VARCHAR(100),
  mitre_phase VARCHAR(100),
  mitre_technique VARCHAR(100),
  confidence FLOAT,
  reason TEXT,
  input_snapshot JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS risk_score FLOAT NOT NULL DEFAULT 0;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS base_risk_score FLOAT;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS adjusted_risk_score FLOAT;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS confidence_score FLOAT;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS learning_adjustment FLOAT DEFAULT 0;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS runtime_adjustment FLOAT DEFAULT 0;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS evidence_adjustment FLOAT DEFAULT 0;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS waf_detected BOOLEAN DEFAULT false;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS tool_blocked BOOLEAN DEFAULT false;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS tool_timeout BOOLEAN DEFAULT false;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS severity VARCHAR(20);
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS next_action VARCHAR(50) NOT NULL DEFAULT 'stop';
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS next_tool VARCHAR(100);
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS mitre_phase VARCHAR(100);
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(100);
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS confidence FLOAT;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS reasoning JSONB;
ALTER TABLE decision_scores ADD COLUMN IF NOT EXISTS input_snapshot JSONB;

CREATE TABLE IF NOT EXISTS tool_tasks (
  id SERIAL PRIMARY KEY,
  target_id INT NOT NULL REFERENCES targets(id),
  open_port_id INT REFERENCES open_ports(id),
  decision_score_id INT REFERENCES decision_scores(id),
  tool_name VARCHAR(100) NOT NULL,
  status VARCHAR(50) DEFAULT 'pending',
  priority INT DEFAULT 5,
  reject_reason TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS decision_score_id INT REFERENCES decision_scores(id);
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending';
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS priority INT DEFAULT 5;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS reject_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_decision_scores_target_id ON decision_scores(target_id);
CREATE INDEX IF NOT EXISTS idx_tool_tasks_target_id ON tool_tasks(target_id);
CREATE INDEX IF NOT EXISTS idx_tool_tasks_status ON tool_tasks(status);

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
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  priority INT DEFAULT 5,
  tool_run VARCHAR(100),
  reject_reason TEXT,
  approval_status VARCHAR(50) NOT NULL DEFAULT 'not_required',
  approval_required BOOLEAN NOT NULL DEFAULT FALSE,
  approval_reason TEXT,
  approved_at TIMESTAMP,
  approved_by VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS decision_score_id INT REFERENCES decision_scores(id);
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending';
UPDATE tool_tasks SET status = 'pending' WHERE status IS NULL;
ALTER TABLE tool_tasks ALTER COLUMN status SET DEFAULT 'pending';
ALTER TABLE tool_tasks ALTER COLUMN status SET NOT NULL;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS priority INT DEFAULT 5;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS tool_run VARCHAR(100);
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS reject_reason TEXT;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approval_status VARCHAR(50) NOT NULL DEFAULT 'not_required';
UPDATE tool_tasks SET approval_status = 'not_required' WHERE approval_status IS NULL;
ALTER TABLE tool_tasks ALTER COLUMN approval_status SET DEFAULT 'not_required';
ALTER TABLE tool_tasks ALTER COLUMN approval_status SET NOT NULL;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approval_required BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE tool_tasks SET approval_required = FALSE WHERE approval_required IS NULL;
ALTER TABLE tool_tasks ALTER COLUMN approval_required SET DEFAULT FALSE;
ALTER TABLE tool_tasks ALTER COLUMN approval_required SET NOT NULL;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approval_reason TEXT;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP;
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS approved_by VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_decision_scores_target_id ON decision_scores(target_id);
CREATE INDEX IF NOT EXISTS idx_tool_tasks_target_id ON tool_tasks(target_id);
CREATE INDEX IF NOT EXISTS idx_tool_tasks_status ON tool_tasks(status);

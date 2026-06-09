-- Recreate decision_scores / tool_tasks if an older schema exists (missing risk_score, etc.).
DROP TABLE IF EXISTS tool_tasks;
DROP TABLE IF EXISTS decision_scores;

CREATE TABLE decision_scores (
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

CREATE TABLE tool_tasks (
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

CREATE INDEX IF NOT EXISTS idx_decision_scores_target_id ON decision_scores(target_id);
CREATE INDEX IF NOT EXISTS idx_tool_tasks_target_id ON tool_tasks(target_id);
CREATE INDEX IF NOT EXISTS idx_tool_tasks_status ON tool_tasks(status);

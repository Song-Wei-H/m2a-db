CREATE TABLE IF NOT EXISTS round_learning_labels (
  id SERIAL PRIMARY KEY,
  target_id INT NOT NULL REFERENCES targets(id),
  scan_run_id INT NULL REFERENCES scan_runs(id),
  round_number INT NOT NULL,
  tool_name VARCHAR(100),
  service VARCHAR(100),
  evidence_type VARCHAR(100),
  current_risk FLOAT,
  next_risk FLOAT,
  current_confidence FLOAT,
  next_confidence FLOAT,
  new_findings INT NOT NULL DEFAULT 0,
  new_cve INT NOT NULL DEFAULT 0,
  new_open_port INT NOT NULL DEFAULT 0,
  evidence_delta INT NOT NULL DEFAULT 0,
  learning_score FLOAT,
  round_value FLOAT NOT NULL DEFAULT 0,
  feature_vector JSONB NOT NULL DEFAULT '{}'::jsonb,
  label_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  dataset_version VARCHAR(50) NOT NULL DEFAULT 'round-dataset-v1',
  feature_version VARCHAR(50) NOT NULL DEFAULT 'round-feature-v1',
  label_version VARCHAR(50) NOT NULL DEFAULT 'round-label-v1',
  feature_vector_version VARCHAR(50) NOT NULL DEFAULT 'round-feature-v1',
  created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS scan_run_id INT NULL REFERENCES scan_runs(id);
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS round_number INT NOT NULL DEFAULT 0;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS tool_name VARCHAR(100);
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS service VARCHAR(100);
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS evidence_type VARCHAR(100);
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS current_risk FLOAT;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS next_risk FLOAT;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS current_confidence FLOAT;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS next_confidence FLOAT;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS new_findings INT NOT NULL DEFAULT 0;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS new_cve INT NOT NULL DEFAULT 0;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS new_open_port INT NOT NULL DEFAULT 0;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS evidence_delta INT NOT NULL DEFAULT 0;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS learning_score FLOAT;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS round_value FLOAT NOT NULL DEFAULT 0;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS feature_vector JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS label_payload JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS dataset_version VARCHAR(50) NOT NULL DEFAULT 'round-dataset-v1';
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS feature_version VARCHAR(50) NOT NULL DEFAULT 'round-feature-v1';
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS label_version VARCHAR(50) NOT NULL DEFAULT 'round-label-v1';
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS feature_vector_version VARCHAR(50) NOT NULL DEFAULT 'round-feature-v1';
ALTER TABLE round_learning_labels ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_round_learning_labels_target_round
  ON round_learning_labels(target_id, round_number);

CREATE INDEX IF NOT EXISTS idx_round_learning_labels_tool_name
  ON round_learning_labels(tool_name);

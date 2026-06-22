CREATE TABLE IF NOT EXISTS normalized_results (
  id SERIAL PRIMARY KEY,
  target_id INT REFERENCES targets(id) ON DELETE CASCADE,
  open_port_id INT REFERENCES open_ports(id) ON DELETE SET NULL,
  tool_result_id INT REFERENCES tool_results(id) ON DELETE CASCADE,
  tool_name VARCHAR(100),
  evidence_type VARCHAR(100),
  normalized_output JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_normalized_results_target_id
  ON normalized_results(target_id);

CREATE INDEX IF NOT EXISTS idx_normalized_results_tool_result_id
  ON normalized_results(tool_result_id);

CREATE INDEX IF NOT EXISTS idx_normalized_results_open_port_id
  ON normalized_results(open_port_id);

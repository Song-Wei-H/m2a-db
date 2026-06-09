CREATE TABLE IF NOT EXISTS scan_results (
  id SERIAL PRIMARY KEY,
  scan_run_id INT NOT NULL REFERENCES scan_runs(id),
  target_id INT NOT NULL REFERENCES targets(id),
  scan_type VARCHAR(50) NOT NULL,
  raw_output TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_run_id ON scan_results(scan_run_id);

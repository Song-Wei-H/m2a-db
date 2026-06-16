CREATE TABLE IF NOT EXISTS port_cve_matches (
  id SERIAL PRIMARY KEY,
  target_id INT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  open_port_id INT NOT NULL REFERENCES open_ports(id) ON DELETE CASCADE,
  cve_id VARCHAR(50) NOT NULL,
  product VARCHAR(255),
  version VARCHAR(255),
  cvss FLOAT,
  epss FLOAT,
  kev BOOLEAN DEFAULT false,
  match_type VARCHAR(50),
  match_confidence FLOAT,
  source TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_port_cve_matches_unique
  ON port_cve_matches(target_id, open_port_id, cve_id, COALESCE(match_type, ''));

CREATE INDEX IF NOT EXISTS idx_port_cve_matches_target_port
  ON port_cve_matches(target_id, open_port_id);

CREATE INDEX IF NOT EXISTS idx_port_cve_matches_cve_id
  ON port_cve_matches(cve_id);

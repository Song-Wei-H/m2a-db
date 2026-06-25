DROP TABLE IF EXISTS tool_tasks, decision_scores, cve_enrichment, worker_jobs, llm_decisions, vulnerabilities, tool_results, scan_results, open_ports, scan_runs, targets CASCADE;

CREATE TABLE targets (
  id SERIAL PRIMARY KEY,
  target VARCHAR(255) NOT NULL,
  target_type VARCHAR(50), -- ip / domain / cidr
  scope VARCHAR(50),       -- internal / external
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE scan_runs (
  id SERIAL PRIMARY KEY,
  target_id INT REFERENCES targets(id),
  round INT DEFAULT 1,
  scan_type VARCHAR(50), -- nmap / nuclei / httpx / nessus / sqlmap
  status VARCHAR(50),    -- pending / running / done / failed
  started_at TIMESTAMP,
  finished_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE scan_results (
  id SERIAL PRIMARY KEY,
  scan_run_id INT NOT NULL REFERENCES scan_runs(id),
  target_id INT NOT NULL REFERENCES targets(id),
  scan_type VARCHAR(50) NOT NULL,
  raw_output TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE open_ports (
  id SERIAL PRIMARY KEY,
  target_id INT REFERENCES targets(id),
  scan_run_id INT REFERENCES scan_runs(id),
  ip VARCHAR(100),
  port INT,
  protocol VARCHAR(20),
  service VARCHAR(100),
  product VARCHAR(255),
  version VARCHAR(255),
  extra_info TEXT,
  state VARCHAR(50) DEFAULT 'open',
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_open_ports_scan_run_port_protocol
  ON open_ports(scan_run_id, port, protocol);
CREATE TABLE decision_scores (
  id SERIAL PRIMARY KEY,
  target_id INT NOT NULL REFERENCES targets(id),
  open_port_id INT REFERENCES open_ports(id),
  risk_score FLOAT NOT NULL,
  base_risk_score FLOAT,
  adjusted_risk_score FLOAT,
  confidence_score FLOAT,
  learning_adjustment FLOAT DEFAULT 0,
  runtime_adjustment FLOAT DEFAULT 0,
  evidence_adjustment FLOAT DEFAULT 0,
  waf_detected BOOLEAN DEFAULT false,
  tool_blocked BOOLEAN DEFAULT false,
  tool_timeout BOOLEAN DEFAULT false,
  severity VARCHAR(20),
  next_action VARCHAR(50) NOT NULL,
  next_tool VARCHAR(100),
  mitre_phase VARCHAR(100),
  mitre_technique VARCHAR(100),
  confidence FLOAT,
  reason TEXT,
  reasoning JSONB,
  input_snapshot JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE tool_tasks (
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
CREATE TABLE tool_results (
  id SERIAL PRIMARY KEY,
  target_id INT REFERENCES targets(id),
  scan_run_id INT REFERENCES scan_runs(id),
  open_port_id INT REFERENCES open_ports(id),
  tool_task_id INT REFERENCES tool_tasks(id),

  tool_name VARCHAR(100), -- httpx / nuclei / dirb / sqlmap / hydra
  command TEXT,
  raw_output TEXT,
  parsed_output JSONB,

  success BOOLEAN DEFAULT false,
  risk_level VARCHAR(50), -- info / low / medium / high / critical
  evidence TEXT,

  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE vulnerabilities (
  id SERIAL PRIMARY KEY,
  target_id INT REFERENCES targets(id),
  open_port_id INT REFERENCES open_ports(id),
  tool_result_id INT REFERENCES tool_results(id),

  cve VARCHAR(50),
  vuln_name VARCHAR(255),
  description TEXT,
  severity VARCHAR(50),
  cvss FLOAT,
  epss FLOAT,
  kev BOOLEAN DEFAULT false,

  mitre_tactic VARCHAR(100),
  mitre_technique VARCHAR(100),

  status VARCHAR(50) DEFAULT 'unverified',
  evidence TEXT,
  remediation TEXT,

  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE llm_decisions (
  id SERIAL PRIMARY KEY,
  target_id INT REFERENCES targets(id),
  scan_run_id INT REFERENCES scan_runs(id),

  input_context JSONB,
  decision JSONB,

  next_action VARCHAR(100), -- continue / stop / remediate
  next_tool VARCHAR(100),
  next_phase VARCHAR(100),
  reason TEXT,
  confidence FLOAT,

  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE cve_enrichment (
  id SERIAL PRIMARY KEY,
  cve VARCHAR(50) UNIQUE NOT NULL,
  cvss FLOAT,
  epss FLOAT,
  kev BOOLEAN DEFAULT false,
  mitre_tactic VARCHAR(100),
  mitre_technique VARCHAR(100),
  description TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_decision_scores_target_id ON decision_scores(target_id);
CREATE INDEX idx_tool_tasks_target_id ON tool_tasks(target_id);
CREATE INDEX idx_tool_tasks_status ON tool_tasks(status);
CREATE TABLE worker_jobs (
  id SERIAL PRIMARY KEY,
  target_id INT REFERENCES targets(id),
  open_port_id INT REFERENCES open_ports(id),

  tool_name VARCHAR(100),
  command TEXT,
  status VARCHAR(50) DEFAULT 'queued', -- queued / running / done / failed
  priority INT DEFAULT 5,

  result_id INT REFERENCES tool_results(id),
  error_message TEXT,

  created_at TIMESTAMP DEFAULT NOW(),
  started_at TIMESTAMP,
  finished_at TIMESTAMP
);

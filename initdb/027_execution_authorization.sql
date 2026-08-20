CREATE TABLE IF NOT EXISTS validation_actions (
    id SERIAL PRIMARY KEY, action_id VARCHAR(150) UNIQUE NOT NULL,
    tool_name VARCHAR(100) NOT NULL, phase VARCHAR(50) NOT NULL,
    validation_tier INTEGER NOT NULL CHECK (validation_tier BETWEEN 0 AND 3),
    execution_identity VARCHAR(255) NOT NULL, template_version VARCHAR(100) NOT NULL,
    parameter_schema JSONB NOT NULL, enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS decision_proposals (
    id SERIAL PRIMARY KEY, investigation_id VARCHAR(100) NOT NULL,
    target_id INTEGER NOT NULL, action_id VARCHAR(150) NOT NULL,
    canonical_parameters JSONB NOT NULL, confidence DOUBLE PRECISION,
    reason TEXT NOT NULL, provider VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'proposed', created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS execution_authorizations (
    id SERIAL PRIMARY KEY, proposal_id INTEGER NOT NULL REFERENCES decision_proposals(id),
    investigation_id VARCHAR(100) NOT NULL, target_id INTEGER NOT NULL,
    action_id VARCHAR(150) NOT NULL, canonical_parameters JSONB NOT NULL,
    parameters_hash VARCHAR(64) NOT NULL, execution_identity VARCHAR(255) NOT NULL,
    template_version VARCHAR(100) NOT NULL,
    validation_tier INTEGER NOT NULL CHECK (validation_tier BETWEEN 0 AND 3),
    scope VARCHAR(255) NOT NULL, execution_limit INTEGER NOT NULL DEFAULT 1 CHECK (execution_limit > 0),
    consumed_count INTEGER NOT NULL DEFAULT 0 CHECK (consumed_count >= 0 AND consumed_count <= execution_limit),
    expires_at TIMESTAMP NOT NULL, authorization_source VARCHAR(100) NOT NULL,
    human_approved_by VARCHAR(255), human_approved_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS investigation_id VARCHAR(100);
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS action_id VARCHAR(150);
ALTER TABLE tool_tasks ADD COLUMN IF NOT EXISTS execution_authorization_id INTEGER REFERENCES execution_authorizations(id);
ALTER TABLE tool_results ADD COLUMN IF NOT EXISTS investigation_id VARCHAR(100);
ALTER TABLE tool_results ADD COLUMN IF NOT EXISTS action_id VARCHAR(150);
CREATE INDEX IF NOT EXISTS idx_decision_proposals_investigation ON decision_proposals(investigation_id);
CREATE INDEX IF NOT EXISTS idx_execution_authorizations_investigation ON execution_authorizations(investigation_id);
CREATE INDEX IF NOT EXISTS idx_tool_tasks_execution_authorization ON tool_tasks(execution_authorization_id);
INSERT INTO validation_actions
    (action_id, tool_name, phase, validation_tier, execution_identity, template_version, parameter_schema, enabled)
VALUES
    ('http_security_headers.collect.v1', 'http_security_headers', 'discovery', 1,
     'builtin:http_security_headers:v1', 'http_security_headers_v1',
     '{"fields":["target","port","protocol","service"]}'::jsonb, TRUE),
    ('nuclei.safe_scan.v1', 'nuclei_safe', 'validation', 2,
     'argv:nuclei:-u:{url}:-severity:critical,high:-rl:5:-timeout:5:-retries:0:-no-color',
     'nuclei_safe', '{"fields":["target","port","protocol","service"]}'::jsonb, TRUE)
ON CONFLICT (action_id) DO UPDATE SET tool_name=EXCLUDED.tool_name, phase=EXCLUDED.phase,
 validation_tier=EXCLUDED.validation_tier, execution_identity=EXCLUDED.execution_identity,
 template_version=EXCLUDED.template_version, parameter_schema=EXCLUDED.parameter_schema, enabled=EXCLUDED.enabled;
-- Historical approval rows are intentionally not converted into authorizations.

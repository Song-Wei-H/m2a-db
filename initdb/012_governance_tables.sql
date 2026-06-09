CREATE TABLE IF NOT EXISTS execution_profiles (
    id SERIAL PRIMARY KEY,
    profile_name VARCHAR(100) UNIQUE NOT NULL,
    container_image VARCHAR(255),
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    network_mode VARCHAR(50) NOT NULL DEFAULT 'bridge',
    readonly_fs BOOLEAN NOT NULL DEFAULT TRUE,
    approval_required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tool_registry (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(50) UNIQUE NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    profile_id VARCHAR(50),
    template_id VARCHAR(50),
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_tool_registry_tool_name
ON tool_registry(tool_name);

CREATE TABLE IF NOT EXISTS tool_requests (
    id SERIAL PRIMARY KEY,
    requested_tool VARCHAR(100) NOT NULL,
    requested_capability VARCHAR(100) NOT NULL,
    evidence_ref VARCHAR(255) NOT NULL,
    reasoning_json JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'pending_review',
    reviewer VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    reviewed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS command_templates (
    id SERIAL PRIMARY KEY,
    template_id VARCHAR(50) UNIQUE NOT NULL,
    tool_name VARCHAR(100) NOT NULL,
    argv_template JSONB NOT NULL,
    allowed_fields JSONB NOT NULL,
    risk_level VARCHAR(50),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_command_templates_tool_name
ON command_templates(tool_name);

-- Tool Requests table for capability expansion requests
CREATE TABLE IF NOT EXISTS tool_requests (
    id SERIAL PRIMARY KEY,
    requested_tool VARCHAR(100) NOT NULL,
    requested_capability VARCHAR(100) NOT NULL,
    evidence_ref VARCHAR(255) NOT NULL,
    reasoning_json JSONB NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending_review',
    reviewer VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    reviewed_at TIMESTAMP
);

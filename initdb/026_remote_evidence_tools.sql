INSERT INTO command_templates
    (template_id, tool_name, argv_template, allowed_fields, risk_level, enabled)
VALUES
    ('tls_certificate_v1', 'tls_certificate', '["remote-evidence", "{target}", "{port}"]'::jsonb, '["target", "port"]'::jsonb, 'low', TRUE),
    ('http_security_headers_v1', 'http_security_headers', '["remote-evidence", "{target}", "{port}"]'::jsonb, '["target", "port"]'::jsonb, 'low', TRUE),
    ('dns_metadata_v1', 'dns_metadata', '["remote-evidence", "{target}"]'::jsonb, '["target"]'::jsonb, 'low', TRUE)
ON CONFLICT (template_id) DO UPDATE SET
    argv_template = EXCLUDED.argv_template,
    allowed_fields = EXCLUDED.allowed_fields,
    risk_level = EXCLUDED.risk_level,
    enabled = EXCLUDED.enabled;

INSERT INTO tool_registry
    (tool_name, enabled, profile_id, template_id, description)
VALUES
    ('tls_certificate', TRUE, 'remote-worker', 'tls_certificate_v1', 'Bounded TLS handshake and certificate metadata collector'),
    ('http_security_headers', TRUE, 'remote-worker', 'http_security_headers_v1', 'Single-request HTTP security-header posture collector'),
    ('dns_metadata', TRUE, 'remote-worker', 'dns_metadata_v1', 'Bounded A, AAAA, and PTR metadata collector')
ON CONFLICT (tool_name) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    profile_id = EXCLUDED.profile_id,
    template_id = EXCLUDED.template_id,
    description = EXCLUDED.description;

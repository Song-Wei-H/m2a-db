-- Phase 3 Batch 1: additive DNS/TLS canonical action identities.
INSERT INTO command_templates
    (template_id, tool_name, argv_template, allowed_fields, risk_level, enabled)
VALUES
    ('dns_metadata_v2', 'dns_metadata',
     '["builtin:dns-metadata", "{normalized_hostname}", "A,AAAA", "PTR-if-IP", "system-resolver", "retry=0"]'::jsonb,
     '["normalized_hostname"]'::jsonb, 'passive', TRUE),
    ('tls_certificate_v2', 'tls_certificate',
     '["builtin:tls-certificate", "{host}", "{port}", "{sni}", "timeout=10", "tls-verify=false"]'::jsonb,
     '["host", "port", "sni"]'::jsonb, 'low', TRUE)
ON CONFLICT (template_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, argv_template=EXCLUDED.argv_template,
    allowed_fields=EXCLUDED.allowed_fields, risk_level=EXCLUDED.risk_level,
    enabled=EXCLUDED.enabled;

UPDATE command_templates SET enabled=FALSE
WHERE tool_name IN ('dns_metadata', 'tls_certificate')
  AND template_id NOT IN ('dns_metadata_v2', 'tls_certificate_v2');

INSERT INTO validation_actions
    (action_id, tool_name, phase, validation_tier, execution_identity,
     template_version, parameter_schema, enabled)
VALUES
    ('dns.metadata_collect.v1', 'dns_metadata', 'discovery', 0,
     'builtin:dns-metadata:getaddrinfo=A,AAAA:ptr=ip-only:fqdn=true:resolver=system:retry=0:timeout=worker-request-ceiling:v2',
     'dns_metadata_v2',
     '{"fields":["target","host","normalized_hostname","port","protocol","service","query_behavior"]}'::jsonb, TRUE),
    ('tls.certificate_collect.v1', 'tls_certificate', 'discovery', 1,
     'builtin:tls-certificate:tcp-connect:tls-client:sni={sni}:timeout=10:tls-verify=false:certificate-sha256=true:v2',
     'tls_certificate_v2',
     '{"fields":["target","host","port","protocol","service","sni","protocol_expectation","timeout_seconds","tls_verify","certificate_sha256"]}'::jsonb, TRUE)
ON CONFLICT (action_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, phase=EXCLUDED.phase,
    validation_tier=EXCLUDED.validation_tier,
    execution_identity=EXCLUDED.execution_identity,
    template_version=EXCLUDED.template_version,
    parameter_schema=EXCLUDED.parameter_schema, enabled=EXCLUDED.enabled;

UPDATE tool_registry SET template_id='dns_metadata_v2' WHERE tool_name='dns_metadata';
UPDATE tool_registry SET template_id='tls_certificate_v2' WHERE tool_name='tls_certificate';
-- Historical ToolTasks and authorizations are intentionally not backfilled.

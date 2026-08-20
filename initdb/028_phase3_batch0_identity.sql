-- Phase 3 Batch 0: additive canonical identities for the two migrated actions.
INSERT INTO command_templates
    (template_id, tool_name, argv_template, allowed_fields, risk_level, enabled)
VALUES
    ('http_security_headers_v2', 'http_security_headers',
     '["builtin:http-security-headers", "{canonical_url}", "HEAD", "/", "M2A-Worker/1", "10"]'::jsonb,
     '["canonical_url"]'::jsonb, 'low', TRUE),
    ('nuclei_safe_v2', 'nuclei_safe',
     '["nuclei", "-u", "{canonical_url}", "-severity", "critical,high", "-rl", "5", "-timeout", "5", "-retries", "0", "-no-color"]'::jsonb,
     '["canonical_url"]'::jsonb, 'medium', TRUE)
ON CONFLICT (template_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, argv_template=EXCLUDED.argv_template,
    allowed_fields=EXCLUDED.allowed_fields, risk_level=EXCLUDED.risk_level,
    enabled=EXCLUDED.enabled;

UPDATE command_templates SET enabled=FALSE
WHERE tool_name IN ('http_security_headers', 'nuclei_safe')
  AND template_id NOT IN ('http_security_headers_v2', 'nuclei_safe_v2');

UPDATE validation_actions SET
    execution_identity='builtin:http-security-headers:head-root:user-agent=M2A-Worker/1:connection=close:timeout=10:tls-verify=false:redirect=false:body=false:v2',
    template_version='http_security_headers_v2',
    parameter_schema='{"fields":["target","host","port","protocol","service","scheme","path","canonical_url","collector"]}'::jsonb
WHERE action_id='http_security_headers.collect.v1';

UPDATE validation_actions SET
    execution_identity='argv:nuclei:-u:{canonical_url}:-severity:critical,high:-rl:5:-timeout:5:-retries:0:-no-color:v2',
    template_version='nuclei_safe_v2',
    parameter_schema='{"fields":["target","host","port","protocol","service","scheme","path","canonical_url","argv"]}'::jsonb
WHERE action_id='nuclei.safe_scan.v1';

-- Historical authorizations are intentionally not rewritten or backfilled.

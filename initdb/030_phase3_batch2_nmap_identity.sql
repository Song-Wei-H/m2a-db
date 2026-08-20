-- Phase 3 Batch 2: additive nmap service-fingerprint canonical identity.
INSERT INTO command_templates
    (template_id, tool_name, argv_template, allowed_fields, risk_level, enabled)
VALUES
    ('nmap_service_v2', 'nmap_service',
     '["nmap", "-sV", "{target}"]'::jsonb,
     '["target"]'::jsonb, 'low', TRUE)
ON CONFLICT (template_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, argv_template=EXCLUDED.argv_template,
    allowed_fields=EXCLUDED.allowed_fields, risk_level=EXCLUDED.risk_level,
    enabled=EXCLUDED.enabled;

UPDATE command_templates SET enabled=FALSE
WHERE tool_name='nmap_service' AND template_id<>'nmap_service_v2';

INSERT INTO validation_actions
    (action_id, tool_name, phase, validation_tier, execution_identity,
     template_version, parameter_schema, enabled)
VALUES
    ('nmap.service_fingerprint.v1', 'nmap_service', 'discovery', 1,
     'argv:nmap:-sV:{target}:ports=default:no-script:no-port-override:timeout=180:nmap-default-retry:v2',
     'nmap_service_v2',
     '{"fields":["target","address","requested_port","port_scope","scan_type","host_discovery","scripts","timeout_seconds","retry_behavior","protocol","service","argv"]}'::jsonb,
     TRUE)
ON CONFLICT (action_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, phase=EXCLUDED.phase,
    validation_tier=EXCLUDED.validation_tier,
    execution_identity=EXCLUDED.execution_identity,
    template_version=EXCLUDED.template_version,
    parameter_schema=EXCLUDED.parameter_schema, enabled=EXCLUDED.enabled;

UPDATE tool_registry SET template_id='nmap_service_v2' WHERE tool_name='nmap_service';
-- Historical ToolTasks and authorizations are intentionally not backfilled.

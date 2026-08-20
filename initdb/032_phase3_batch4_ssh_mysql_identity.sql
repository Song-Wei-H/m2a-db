-- Phase 3 Batch 4: bounded SSH algorithm and MySQL server-info identities.
INSERT INTO command_templates
    (template_id, tool_name, argv_template, allowed_fields, risk_level, enabled)
VALUES
    ('ssh_algorithms_enum_v2', 'ssh-enum',
     '["nmap", "--script", "ssh2-enum-algos", "-p", "{port}", "{target}"]'::jsonb,
     '["port", "target"]'::jsonb, 'low', TRUE),
    ('mysql_server_info_v2', 'mysql-info',
     '["nmap", "--script", "mysql-info", "-p", "{port}", "{target}"]'::jsonb,
     '["port", "target"]'::jsonb, 'low', TRUE)
ON CONFLICT (template_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, argv_template=EXCLUDED.argv_template,
    allowed_fields=EXCLUDED.allowed_fields, risk_level=EXCLUDED.risk_level,
    enabled=EXCLUDED.enabled;

UPDATE command_templates SET enabled=FALSE
WHERE tool_name='ssh-enum' AND template_id<>'ssh_algorithms_enum_v2';
UPDATE command_templates SET enabled=FALSE
WHERE tool_name='mysql-info' AND template_id<>'mysql_server_info_v2';

INSERT INTO validation_actions
    (action_id, tool_name, phase, validation_tier, execution_identity,
     template_version, parameter_schema, enabled)
VALUES
    ('ssh.algorithms_enum.v1', 'ssh-enum', 'discovery', 1,
     'argv:nmap:--script:ssh2-enum-algos:-p:{port}:{target}:algorithm-enumeration-only:timeout=180:nmap-default-retry:v2',
     'ssh_algorithms_enum_v2',
     '{"fields":["target","host","port","protocol","service","script","scripts","scan_type","authentication","retry_behavior","timeout_seconds","argv"]}'::jsonb,
     TRUE),
    ('mysql.server_info.v1', 'mysql-info', 'discovery', 1,
     'argv:nmap:--script:mysql-info:-p:{port}:{target}:server-info-only:no-auth:timeout=180:nmap-default-retry:v2',
     'mysql_server_info_v2',
     '{"fields":["target","host","port","protocol","service","script","scripts","scan_type","authentication","retry_behavior","timeout_seconds","argv"]}'::jsonb,
     TRUE)
ON CONFLICT (action_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, phase=EXCLUDED.phase,
    validation_tier=EXCLUDED.validation_tier,
    execution_identity=EXCLUDED.execution_identity,
    template_version=EXCLUDED.template_version,
    parameter_schema=EXCLUDED.parameter_schema, enabled=EXCLUDED.enabled;

UPDATE tool_registry SET template_id='ssh_algorithms_enum_v2' WHERE tool_name='ssh-enum';
UPDATE tool_registry SET template_id='mysql_server_info_v2' WHERE tool_name='mysql-info';
-- Historical ToolTasks and authorizations are intentionally not backfilled.

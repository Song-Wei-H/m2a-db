-- Phase 3 Batch 3: additive bounded HTTPx web-probe canonical identity.
INSERT INTO command_templates
    (template_id, tool_name, argv_template, allowed_fields, risk_level, enabled)
VALUES
    ('httpx_web_probe_v2', 'httpx_basic',
     '["httpx", "-u", "{canonical_url}", "-json", "-title", "-tech-detect", "-status-code"]'::jsonb,
     '["canonical_url"]'::jsonb, 'low', TRUE)
ON CONFLICT (template_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, argv_template=EXCLUDED.argv_template,
    allowed_fields=EXCLUDED.allowed_fields, risk_level=EXCLUDED.risk_level,
    enabled=EXCLUDED.enabled;

UPDATE command_templates SET enabled=FALSE
WHERE tool_name='httpx_basic' AND template_id<>'httpx_web_probe_v2';

INSERT INTO validation_actions
    (action_id, tool_name, phase, validation_tier, execution_identity,
     template_version, parameter_schema, enabled)
VALUES
    ('httpx.web_probe.v1', 'httpx_basic', 'discovery', 1,
     'argv:httpx:-u:{canonical_url}:-json:-title:-tech-detect:-status-code:method=probe:path=/:redirect=false:retry=httpx-default:timeout=180:v2',
     'httpx_web_probe_v2',
     '{"fields":["target","host","scheme","port","protocol","service","path","canonical_url","method","redirect_policy","retry_behavior","timeout_seconds","argv"]}'::jsonb,
     TRUE)
ON CONFLICT (action_id) DO UPDATE SET
    tool_name=EXCLUDED.tool_name, phase=EXCLUDED.phase,
    validation_tier=EXCLUDED.validation_tier,
    execution_identity=EXCLUDED.execution_identity,
    template_version=EXCLUDED.template_version,
    parameter_schema=EXCLUDED.parameter_schema, enabled=EXCLUDED.enabled;

UPDATE tool_registry SET template_id='httpx_web_probe_v2' WHERE tool_name='httpx_basic';
-- Historical ToolTasks and authorizations are intentionally not backfilled.

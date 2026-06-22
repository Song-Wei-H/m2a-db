CREATE OR REPLACE VIEW learning_tool_score AS
SELECT
  lf.tool_name,
  COUNT(*)::INT AS feedback_count,
  COUNT(*) FILTER (WHERE lf.success IS TRUE)::INT AS success_count,
  AVG(lf.learning_score)::FLOAT AS avg_learning_score,
  COALESCE(AVG(lf.learning_score), 0.5)::FLOAT AS final_learning_score
FROM learning_feedback lf
GROUP BY lf.tool_name;

CREATE OR REPLACE VIEW target_summary AS
WITH open_port_counts AS (
  SELECT
    target_id,
    COUNT(*)::INT AS open_port_count,
    MAX(created_at) AS last_open_port_at
  FROM open_ports
  GROUP BY target_id
),
tool_result_counts AS (
  SELECT
    target_id,
    COUNT(*)::INT AS tool_result_count,
    MAX(created_at) AS last_tool_result_at
  FROM tool_results
  GROUP BY target_id
),
decision_stats AS (
  SELECT
    target_id,
    COUNT(*)::INT AS decision_score_count,
    MAX(risk_score)::FLOAT AS highest_risk_score,
    (ARRAY_AGG(severity ORDER BY risk_score DESC NULLS LAST, created_at DESC))[1] AS highest_severity,
    MAX(created_at) AS last_decision_at
  FROM decision_scores
  GROUP BY target_id
)
SELECT
  t.id AS target_id,
  t.target,
  t.target_type,
  t.scope,
  t.status,
  COALESCE(op.open_port_count, 0) AS open_port_count,
  COALESCE(tr.tool_result_count, 0) AS tool_result_count,
  COALESCE(ds.decision_score_count, 0) AS decision_score_count,
  ds.highest_risk_score,
  ds.highest_severity,
  GREATEST(
    t.created_at,
    COALESCE(op.last_open_port_at, t.created_at),
    COALESCE(tr.last_tool_result_at, t.created_at),
    COALESCE(ds.last_decision_at, t.created_at)
  ) AS last_activity_at
FROM targets t
LEFT JOIN open_port_counts op ON op.target_id = t.id
LEFT JOIN tool_result_counts tr ON tr.target_id = t.id
LEFT JOIN decision_stats ds ON ds.target_id = t.id;

CREATE OR REPLACE VIEW risk_ranking AS
SELECT
  ds.target_id,
  t.target,
  ds.open_port_id,
  op.port,
  op.service,
  ds.risk_score,
  ds.severity,
  ds.next_action,
  ds.next_tool,
  ds.mitre_phase,
  ds.mitre_technique,
  ds.reason,
  ds.created_at
FROM decision_scores ds
JOIN targets t ON t.id = ds.target_id
LEFT JOIN open_ports op ON op.id = ds.open_port_id
ORDER BY ds.risk_score DESC NULLS LAST, ds.created_at DESC;

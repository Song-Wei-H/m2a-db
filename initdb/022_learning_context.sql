CREATE OR REPLACE VIEW learning_tool_context_score AS
SELECT
  lf.tool_name,
  COALESCE(NULLIF(lf.service, ''), 'unknown') AS service,
  COALESCE(NULLIF(lf.evidence_type, ''), 'unknown') AS evidence_type,
  'unknown'::TEXT AS port_bucket,
  COUNT(*)::INT AS total_runs,
  COUNT(*) FILTER (WHERE lf.success IS TRUE)::INT AS success_count,
  COUNT(*) FILTER (WHERE lf.success IS FALSE)::INT AS failure_count,
  CASE
    WHEN COUNT(*) = 0 THEN 0.5
    ELSE (COUNT(*) FILTER (WHERE lf.success IS TRUE)::FLOAT / COUNT(*)::FLOAT)
  END AS success_rate,
  COALESCE(AVG(lf.learning_score), 0.5)::FLOAT AS avg_learning_score,
  MAX(lf.created_at) AS last_seen
FROM learning_feedback lf
GROUP BY
  lf.tool_name,
  COALESCE(NULLIF(lf.service, ''), 'unknown'),
  COALESCE(NULLIF(lf.evidence_type, ''), 'unknown');

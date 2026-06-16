-- learning_feedback.decision_id stores DecisionScore.id, not LlmDecision.id.
ALTER TABLE learning_feedback
    DROP CONSTRAINT IF EXISTS learning_feedback_decision_id_fkey;

UPDATE learning_feedback
SET decision_id = NULL
WHERE decision_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM decision_scores
      WHERE decision_scores.id = learning_feedback.decision_id
  );

ALTER TABLE learning_feedback
    ADD CONSTRAINT learning_feedback_decision_id_fkey
    FOREIGN KEY (decision_id)
    REFERENCES decision_scores(id)
    ON DELETE SET NULL;

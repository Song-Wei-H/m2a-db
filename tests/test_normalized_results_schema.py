from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SQL = (ROOT / "initdb" / "018_normalized_results.sql").read_text()


def test_normalized_results_migration_creates_traceable_evidence_table():
    assert "CREATE TABLE IF NOT EXISTS normalized_results" in SQL
    for column in (
        "target_id",
        "open_port_id",
        "tool_result_id",
        "tool_name",
        "evidence_type",
        "normalized_output JSONB",
    ):
        assert column in SQL


def test_normalized_results_migration_adds_lookup_indexes():
    assert "idx_normalized_results_target_id" in SQL
    assert "idx_normalized_results_tool_result_id" in SQL
    assert "idx_normalized_results_open_port_id" in SQL

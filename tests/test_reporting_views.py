from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from worker.learning_engine import get_tool_learning_score


ROOT = Path(__file__).resolve().parents[1]
REPORTING_VIEWS_SQL = (ROOT / "initdb" / "017_reporting_views.sql").read_text()


class FakeFirstResult:
    def __init__(self, row):
        self._row = row

    def first(self):
        return self._row


def test_reporting_views_migration_creates_required_views():
    assert "CREATE OR REPLACE VIEW learning_tool_score" in REPORTING_VIEWS_SQL
    assert "CREATE OR REPLACE VIEW target_summary" in REPORTING_VIEWS_SQL
    assert "CREATE OR REPLACE VIEW risk_ranking" in REPORTING_VIEWS_SQL


def test_target_summary_view_exposes_dashboard_columns():
    for column in (
        "target_id",
        "target_type",
        "scope",
        "status",
        "open_port_count",
        "tool_result_count",
        "decision_score_count",
        "highest_risk_score",
        "highest_severity",
        "last_activity_at",
    ):
        assert column in REPORTING_VIEWS_SQL

    assert "FROM targets t" in REPORTING_VIEWS_SQL
    assert "LEFT JOIN open_port_counts" in REPORTING_VIEWS_SQL
    assert "LEFT JOIN tool_result_counts" in REPORTING_VIEWS_SQL
    assert "LEFT JOIN decision_stats" in REPORTING_VIEWS_SQL


def test_risk_ranking_view_is_target_scoped_and_ordered():
    for column in (
        "ds.target_id",
        "t.target",
        "ds.open_port_id",
        "op.port",
        "op.service",
        "ds.risk_score",
        "ds.severity",
        "ds.next_action",
        "ds.next_tool",
        "ds.mitre_phase",
        "ds.mitre_technique",
        "ds.reason",
        "ds.created_at",
    ):
        assert column in REPORTING_VIEWS_SQL

    assert "JOIN targets t ON t.id = ds.target_id" in REPORTING_VIEWS_SQL
    assert "ORDER BY ds.risk_score DESC" in REPORTING_VIEWS_SQL


def test_learning_tool_score_view_exposes_expected_aggregate_columns():
    for column in (
        "tool_name",
        "feedback_count",
        "success_count",
        "avg_learning_score",
        "final_learning_score",
    ):
        assert column in REPORTING_VIEWS_SQL

    assert "FROM learning_feedback lf" in REPORTING_VIEWS_SQL
    assert "GROUP BY lf.tool_name" in REPORTING_VIEWS_SQL


@pytest.mark.asyncio
async def test_learning_tool_score_empty_result_returns_default_without_crash():
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock(return_value=FakeFirstResult(None))

    assert await get_tool_learning_score(session, "nmap_service") == 0.5

import re
from pathlib import Path

from app.models import ToolTask


EXPECTED_NULLABILITY = {
    "tool_name": False,
    "status": False,
    "target_id": False,
    "open_port_id": True,
    "decision_score_id": True,
    "tool_run": True,
    "approval_required": False,
    "approval_status": False,
    "approval_reason": True,
    "reject_reason": True,
    "approved_at": True,
    "approved_by": True,
}


def _initdb_sql() -> str:
    return "\n".join(path.read_text(encoding="utf-8").lower() for path in sorted(Path("initdb").glob("*.sql")))


def _column_definition(sql: str, column_name: str) -> str:
    table_match = re.search(
        r"create table(?: if not exists)? tool_tasks\s*\((.*?)\);",
        sql,
        flags=re.DOTALL,
    )
    assert table_match, "tool_tasks CREATE TABLE block missing from initdb migrations"
    table_sql = table_match.group(1)
    matches = re.findall(rf"^\s*{column_name}\s+[^,\n;]+", table_sql, flags=re.MULTILINE)
    assert matches, f"{column_name} missing from initdb migrations"
    return matches[0]


def test_tooltask_orm_nullability_matches_expected_contract():
    columns = ToolTask.__table__.columns

    for column_name, expected_nullable in EXPECTED_NULLABILITY.items():
        assert columns[column_name].nullable is expected_nullable


def test_tooltask_migrations_express_required_nullability():
    sql = _initdb_sql()

    for column_name, expected_nullable in EXPECTED_NULLABILITY.items():
        definition = _column_definition(sql, column_name)
        if expected_nullable:
            assert "not null" not in definition
        else:
            assert "not null" in definition


def test_tooltask_lifecycle_alignment_migration_is_idempotent():
    sql = Path("initdb/021_tooltask_lifecycle_alignment.sql").read_text(encoding="utf-8").lower()

    assert "add column if not exists tool_run" in sql
    assert "add column if not exists status" in sql
    assert "update tool_tasks set status" in sql
    assert "alter column status set not null" in sql
    assert "add column if not exists approval_status" in sql
    assert "alter column approval_status set not null" in sql
    assert "add column if not exists approval_required" in sql
    assert "alter column approval_required set not null" in sql

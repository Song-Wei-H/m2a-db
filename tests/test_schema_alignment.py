import re
from pathlib import Path

from app.models import ToolTask


REQUIRED_TOOL_TASK_COLUMNS = {
    "approval_required",
    "approval_status",
    "approval_reason",
    "reject_reason",
    "approved_at",
    "approved_by",
}


def _initdb_sql() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(Path("initdb").glob("*.sql")))


def test_tooltask_orm_exposes_approval_columns():
    orm_columns = set(ToolTask.__table__.columns.keys())

    assert REQUIRED_TOOL_TASK_COLUMNS <= orm_columns


def test_tooltask_migrations_expose_approval_columns():
    sql = _initdb_sql().lower()

    for column in REQUIRED_TOOL_TASK_COLUMNS:
        assert re.search(rf"\b{column}\b", sql), f"{column} missing from initdb migrations"


def test_approval_router_referenced_fields_exist_on_orm():
    router_source = Path("app/routers/approval.py").read_text(encoding="utf-8")
    used_fields = {
        "approval_required",
        "approval_status",
        "approval_reason",
        "reject_reason",
        "approved_at",
        "approved_by",
    }
    orm_columns = set(ToolTask.__table__.columns.keys())

    for field in used_fields:
        if f"task.{field}" in router_source or f"ToolTask.{field}" in router_source:
            assert field in orm_columns


def test_approval_router_and_schema_are_aligned():
    sql = _initdb_sql().lower()
    orm_columns = set(ToolTask.__table__.columns.keys())

    assert REQUIRED_TOOL_TASK_COLUMNS <= orm_columns
    for column in REQUIRED_TOOL_TASK_COLUMNS:
        assert column in sql

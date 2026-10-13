"""Static contract checks; PostgreSQL execution is proven only by host validation."""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from app.models import Base


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "initdb" / "037_llm_evidence_tables.sql"
TABLES = ("evidence_confidence", "llm_recommendations")


def _pg_type(column) -> str:
    kind = column.type
    if isinstance(kind, Integer):
        return "SERIAL" if column.primary_key and column.autoincrement else "INTEGER"
    if isinstance(kind, Float):
        return "DOUBLE PRECISION"
    if isinstance(kind, Text):
        return "TEXT"
    if isinstance(kind, String):
        return f"VARCHAR({kind.length})"
    if isinstance(kind, JSONB):
        return "JSONB"
    if isinstance(kind, DateTime):
        assert kind.timezone is False
        return "TIMESTAMP WITHOUT TIME ZONE"
    if isinstance(kind, Boolean):
        return "BOOLEAN"
    raise AssertionError(f"Unexpected ORM type {kind!r} for {column}")


def _create_table_body(sql: str, table: str) -> str:
    match = re.search(
        rf"CREATE\s+TABLE\s+public\.{table}\s*\((.*?)\n\);",
        sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert match, f"missing CREATE TABLE for {table}"
    return match.group(1)


def test_migration_037_columns_match_sqlalchemy_models() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for table_name in TABLES:
        model = Base.metadata.tables[table_name]
        body = _create_table_body(sql, table_name)
        declarations: dict[str, str] = {}
        for raw_line in body.splitlines():
            line = raw_line.strip().rstrip(",")
            if not line or line.upper().startswith(("PRIMARY KEY", "CONSTRAINT ")):
                continue
            name, _, declaration = line.partition(" ")
            declarations[name] = declaration.upper()
        assert set(declarations) == {column.name for column in model.columns}
        for column in model.columns:
            declaration = declarations[column.name]
            assert declaration.startswith(_pg_type(column)), (table_name, column.name, declaration)
            if not (column.primary_key and column.autoincrement):
                assert ("NOT NULL" in declaration) is (not column.nullable)
            if column.primary_key:
                assert "PRIMARY KEY" in declaration
            if column.name == "created_at":
                assert "DEFAULT NOW()" in declaration
            elif table_name == "llm_recommendations" and column.name == "approved":
                assert "DEFAULT FALSE" in declaration
            else:
                assert "DEFAULT" not in declaration


def test_migration_037_is_guarded_forward_only_and_does_not_invent_relations() -> None:
    sql = MIGRATION.read_text(encoding="utf-8").upper()
    assert "TO_REGCLASS('PUBLIC.VULNERABILITY_CANDIDATES') IS NULL" in sql
    assert "VULNERABILITY_CANDIDATES_VALIDATION_COVERAGE_VALUES" in sql
    assert "IDX_VULNERABILITY_CANDIDATES_VALIDATION_COVERAGE" in sql
    assert "VULNERABILITY_CANDIDATES'::REGCLASS" in sql
    assert "REFUSES PRE-EXISTING OR PARTIAL" in sql
    assert "CREATE TABLE IF NOT EXISTS" not in sql
    assert "CREATE INDEX IF NOT EXISTS" not in sql
    assert "DROP TABLE" not in sql
    assert "REFERENCES " not in sql
    assert "CREATE INDEX" not in sql
    assert "CREATE UNIQUE INDEX" not in sql


def test_host_runner_applies_and_verifies_037_in_all_profiles() -> None:
    runner = (ROOT / "scripts" / "Invoke-MigrationSmoke.ps1").read_text(encoding="utf-8")
    host = (ROOT / "scripts" / "Invoke-GadePreExpHostValidation.ps1").read_text(encoding="utf-8")
    assert "Last = 37" in runner
    assert "Assert-Migration037Schema $container.Id" in runner
    assert "Assert-Migration037PreconditionFails $container.Id" in runner
    assert "Assert-Migration037PartialObjectRollback $container.Id" in runner
    assert "-SingleTransaction" in runner
    assert "APPLY-001-037" in runner
    assert "APPLY-LEGACY-001-037" in runner
    assert "APPLY-LEGACY025-001-037" in runner
    assert "Fresh schema migrations 001-037" in host
    assert "Legacy 033-037 compatibility" in host
    assert "initdb/037_llm_evidence_tables.sql" in host


def test_migration_037_negative_test_requires_exact_postgres_prerequisite_failure() -> None:
    runner = (ROOT / "scripts" / "Invoke-MigrationSmoke.ps1").read_text(encoding="utf-8")
    oracle = (ROOT / "scripts" / "GadeMigration037Oracle.ps1").read_text(encoding="utf-8")
    assert "'ON_ERROR_STOP=1'" in runner
    assert "-SingleTransaction" in runner
    assert "TargetIdentityValid $targetIdentityValid" in runner
    assert "-ne 3" in oracle
    assert "Migration\\s+037\\s+requires\\s+migration\\s+036\\s+validation_coverage" in oracle
    assert "partial_migration037_schema_detected" in oracle
    assert "NULL|NULL" in oracle

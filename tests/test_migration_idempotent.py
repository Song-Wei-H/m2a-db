from pathlib import Path


MIGRATIONS_TO_CHECK = [
    Path("initdb/020_architecture_hardening.sql"),
    Path("initdb/021_tooltask_lifecycle_alignment.sql"),
    Path("initdb/duplicate_audit.sql"),
    Path("initdb/dedupe.sql"),
]


def test_architecture_hardening_migration_is_idempotent():
    sql = Path("initdb/020_architecture_hardening.sql").read_text(encoding="utf-8").lower()

    assert "add column if not exists approval_reason" in sql
    assert "add column if not exists reject_reason" in sql
    assert "add column if not exists approved_at" in sql
    assert "add column if not exists approved_by" in sql
    assert "create unique index" not in sql


def test_duplicate_audit_is_read_only():
    sql = Path("initdb/duplicate_audit.sql").read_text(encoding="utf-8").lower()

    assert sql.lstrip().startswith("-- audit")
    assert "select" in sql
    assert "update " not in sql
    assert "delete " not in sql
    assert "create " not in sql


def test_dedupe_script_is_repeatable_status_update():
    sql = Path("initdb/dedupe.sql").read_text(encoding="utf-8").lower()

    assert "row_number()" in sql
    assert "status = 'rejected'" in sql
    assert "coalesce(reject_reason" in sql
    assert "delete " not in sql


def test_migration_sql_files_avoid_non_idempotent_create_index():
    for path in MIGRATIONS_TO_CHECK:
        sql = path.read_text(encoding="utf-8").lower()
        assert "create index " not in sql
        assert "create unique index " not in sql

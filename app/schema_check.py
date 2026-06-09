"""Verify DB columns exist before INSERT to avoid UndefinedColumnError."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Columns required by dispatcher INSERT into scan_results
SCAN_RESULTS_REQUIRED = frozenset(
    {"scan_run_id", "target_id", "scan_type", "raw_output"}
)


async def get_table_columns(db: AsyncSession, table_name: str) -> set[str]:
    result = await db.execute(
        text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = :table
            """
        ),
        {"table": table_name},
    )
    return {row[0] for row in result.all()}


async def assert_scan_results_schema(db: AsyncSession) -> None:
    columns = await get_table_columns(db, "scan_results")
    if not columns:
        raise RuntimeError(
            "Table scan_results does not exist. "
            "Run initdb/002_scan_results.sql or initdb/003_scan_results_legacy_columns.sql"
        )
    missing = SCAN_RESULTS_REQUIRED - columns
    if missing:
        raise RuntimeError(
            f"scan_results is missing required columns: {sorted(missing)}. "
            "Run initdb/003_scan_results_legacy_columns.sql before starting the dispatcher."
        )

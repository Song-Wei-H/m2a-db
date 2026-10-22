"""Validate only the OSV migration dependency path on disposable PostgreSQL 16.

Required: M2A_OSV_PG_TEST_URL must point to loopback database osv_test_core.
The script applies only migrations 018, 025, 035, and 038 to that empty DB,
then creates two disposable sibling DBs to test the 035-absent and rollback/
partial-schema cases. It never reads application secrets or production data.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path

import asyncpg
from sqlalchemy.engine import make_url


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = {
    name: (ROOT / "initdb" / name).read_text(encoding="utf-8")
    for name in (
        "018_normalized_results.sql",
        "025_normalized_results_schema_alignment.sql",
        "035_vulnerability_work_queue.sql",
        "038_osv_package_enrichment.sql",
    )
}
PARENT_TABLES = """
CREATE TABLE public.targets (id SERIAL PRIMARY KEY);
CREATE TABLE public.open_ports (id SERIAL PRIMARY KEY);
CREATE TABLE public.tool_results (id SERIAL PRIMARY KEY);
CREATE TABLE public.authorization_decisions (id SERIAL PRIMARY KEY);
CREATE TABLE public.execution_authorizations (id SERIAL PRIMARY KEY);
CREATE TABLE public.tool_tasks (id SERIAL PRIMARY KEY);
"""


def _safe_base_url() -> tuple[str, str]:
    raw = os.environ.get("M2A_OSV_PG_TEST_URL")
    if not raw:
        raise SystemExit("M2A_OSV_PG_TEST_URL is required; no DB connection was attempted")
    url = make_url(raw)
    if url.drivername != "postgresql+asyncpg":
        raise SystemExit("test URL must use postgresql+asyncpg")
    if url.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("test URL must use loopback only")
    if url.database != "osv_test_core" or url.database == "m2a_pentest":
        raise SystemExit("test URL database must be exactly osv_test_core")
    if url.port == 15432:
        raise SystemExit("formal PostgreSQL port is forbidden")
    connect_url = url.set(drivername="postgresql").render_as_string(hide_password=False)
    return connect_url, url.port or 5432


async def _connect(base_url: str, database: str) -> asyncpg.Connection:
    url = make_url(base_url).set(database=database)
    return await asyncpg.connect(url.render_as_string(hide_password=False))


async def _create_database(base_url: str, name: str) -> None:
    admin = await _connect(base_url, "postgres")
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()


async def _setup_normalized_schema(connection: asyncpg.Connection, *, include_035: bool) -> None:
    async with connection.transaction():
        await connection.execute(PARENT_TABLES)
        await connection.execute(MIGRATIONS["018_normalized_results.sql"])
        await connection.execute(MIGRATIONS["025_normalized_results_schema_alignment.sql"])
        if include_035:
            await connection.execute(MIGRATIONS["035_vulnerability_work_queue.sql"])


async def _assert_osv_schema(connection: asyncpg.Connection) -> dict:
    columns = await connection.fetch("""
        SELECT table_name, column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name IN ('osv_package_query_cache','osv_normalized_evidence')
        ORDER BY table_name, ordinal_position
    """)
    constraints = await connection.fetch("""
        SELECT rel.relname AS table_name, con.conname, con.contype::text AS contype,
               con.confdeltype::text AS confdeltype
        FROM pg_constraint con JOIN pg_class rel ON rel.oid=con.conrelid
        JOIN pg_namespace ns ON ns.oid=rel.relnamespace
        WHERE ns.nspname='public' AND rel.relname IN ('osv_package_query_cache','osv_normalized_evidence')
        ORDER BY rel.relname, con.conname
    """)
    indexes = await connection.fetch("""
        SELECT tablename, indexname FROM pg_indexes
        WHERE schemaname='public' AND tablename IN ('osv_package_query_cache','osv_normalized_evidence')
        ORDER BY tablename, indexname
    """)
    tables = await connection.fetchval("""
        SELECT count(*) FROM information_schema.tables
        WHERE table_schema='public' AND table_name IN ('osv_package_query_cache','osv_normalized_evidence')
    """)
    if tables != 2:
        raise AssertionError(f"expected both OSV tables, got {tables}")
    if not any(row["conname"] == "uq_osv_normalized_evidence_identity" and row["contype"] == "u" for row in constraints):
        raise AssertionError("missing unique NormalizedResult/identity constraint")
    if not any(row["table_name"] == "osv_package_query_cache" and row["contype"] == "u" for row in constraints):
        raise AssertionError("missing query cache unique cache_key constraint")
    if not any(row["table_name"] == "osv_normalized_evidence" and row["contype"] == "f" and row["confdeltype"] == "c" for row in constraints):
        raise AssertionError("missing normalized_results ON DELETE CASCADE foreign key")
    if not any(row["table_name"] == "osv_normalized_evidence" and row["contype"] == "f" and row["confdeltype"] == "n" for row in constraints):
        raise AssertionError("missing cache_id ON DELETE SET NULL foreign key")
    expected_indexes = {
        "idx_osv_package_query_cache_status_retry",
        "idx_osv_package_query_cache_expiry",
        "idx_osv_normalized_evidence_normalized_result",
        "idx_osv_normalized_evidence_cache_id",
    }
    if not expected_indexes.issubset({row["indexname"] for row in indexes}):
        raise AssertionError("one or more expected OSV indexes are missing")
    type_map = {(row["table_name"], row["column_name"]): row["data_type"] for row in columns}
    for key in (
        ("osv_package_query_cache", "response_summary"),
        ("osv_normalized_evidence", "package_identity"),
        ("osv_normalized_evidence", "result_summary"),
    ):
        if type_map.get(key) != "jsonb":
            raise AssertionError(f"expected jsonb at {key}")
    return {
        "column_count": len(columns),
        "constraints": [dict(row) for row in constraints],
        "indexes": [dict(row) for row in indexes],
    }


async def main() -> None:
    base_url, port = _safe_base_url()
    core = await _connect(base_url, "osv_test_core")
    try:
        version_num = int(await core.fetchval("SHOW server_version_num"))
        if not 160000 <= version_num < 170000:
            raise AssertionError(f"expected PostgreSQL 16, got server_version_num={version_num}")
        preexisting = await core.fetchval("SELECT to_regclass('public.normalized_results')")
        if preexisting is not None:
            raise AssertionError("core DB is not empty; refusing to apply migration validation")
        await _setup_normalized_schema(core, include_035=True)
        await core.execute(MIGRATIONS["038_osv_package_enrichment.sql"])
        core_schema = await _assert_osv_schema(core)
        has_candidates = await core.fetchval("SELECT to_regclass('public.vulnerability_candidates') IS NOT NULL")
        if not has_candidates:
            raise AssertionError("035 was not applied to the primary migration fixture")
    finally:
        await core.close()

    suffix = uuid.uuid4().hex[:8]
    no035_name = f"osv_test_no035_{suffix}"
    partial_name = f"osv_test_partial_{suffix}"
    await _create_database(base_url, no035_name)
    no035 = await _connect(base_url, no035_name)
    try:
        await _setup_normalized_schema(no035, include_035=False)
        if await no035.fetchval("SELECT to_regclass('public.vulnerability_candidates') IS NOT NULL"):
            raise AssertionError("no-035 fixture unexpectedly contains vulnerability_candidates")
        # Prove PostgreSQL transactional DDL rollback: all Migration 038 objects
        # must disappear when the enclosing transaction aborts.
        try:
            async with no035.transaction():
                await no035.execute(MIGRATIONS["038_osv_package_enrichment.sql"])
                await no035.execute("SELECT 1 / 0")
        except asyncpg.DivisionByZeroError:
            pass
        else:
            raise AssertionError("forced transaction failure did not abort")
        if await no035.fetchval("SELECT to_regclass('public.osv_package_query_cache') IS NOT NULL"):
            raise AssertionError("Migration 038 objects survived transaction rollback")
        await no035.execute(MIGRATIONS["038_osv_package_enrichment.sql"])
        no035_schema = await _assert_osv_schema(no035)
        if await no035.fetchval("SELECT to_regclass('public.vulnerability_candidates') IS NOT NULL"):
            raise AssertionError("Migration 038 created or required vulnerability_candidates")
    finally:
        await no035.close()

    await _create_database(base_url, partial_name)
    partial = await _connect(base_url, partial_name)
    try:
        await _setup_normalized_schema(partial, include_035=False)
        await partial.execute("CREATE TABLE public.osv_package_query_cache (id integer)")
        try:
            async with partial.transaction():
                await partial.execute(MIGRATIONS["038_osv_package_enrichment.sql"])
        except asyncpg.RaiseError:
            pass
        else:
            raise AssertionError("Migration 038 must refuse a partial/pre-existing OSV schema")
        if await partial.fetchval("SELECT to_regclass('public.osv_normalized_evidence') IS NOT NULL"):
            raise AssertionError("partial-schema failure left a second OSV table")
    finally:
        await partial.close()

    print(json.dumps({
        "status": "PASS",
        "postgres_version_num": version_num,
        "loopback_port": port,
        "core_database": "osv_test_core",
        "core_migration_order": ["018", "025", "035", "038"],
        "no_035_database": no035_name,
        "no_035_migration_order": ["018", "025", "038"],
        "no_035_absence_verified": "vulnerability_candidates absent before/after Migration 038",
        "transaction_rollback": "Migration 038 DDL rolled back after forced error; clean reapply succeeded",
        "partial_schema": partial_name,
        "partial_schema_fail_closed": "pre-existing cache table rejected; no evidence table created",
        "core_schema": core_schema,
        "no_035_schema": no035_schema,
    }, ensure_ascii=False, sort_keys=True, default=str))


if __name__ == "__main__":
    asyncio.run(main())

from pathlib import Path


def test_migration_038_is_forward_only_and_tracks_query_evidence():
    sql = Path("initdb/038_osv_package_enrichment.sql").read_text(encoding="utf-8").lower()

    assert "create table public.osv_package_query_cache" in sql
    assert "create table public.osv_normalized_evidence" in sql
    assert "references public.normalized_results(id) on delete cascade" in sql
    assert "unique (normalized_result_id, identity_key)" in sql
    assert "response_sha256" in sql
    assert "last_attempt_sha256" in sql
    assert "retrieved_at" in sql
    assert "retry_after" in sql
    assert "match_confidence" in sql
    assert "unsupported" in sql
    assert "partial" in sql
    assert "no_match" in sql
    assert "no_vulnerabilities" not in sql
    assert "drop table" not in sql
    assert "truncate " not in sql
    assert "delete from " not in sql

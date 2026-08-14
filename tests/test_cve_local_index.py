from pathlib import Path

from worker.cve_local_index import query_local_candidates, rebuild_local_index


def test_local_index_prioritizes_kev_cvss_and_limits_candidates(tmp_path: Path):
    path = tmp_path / "cve.sqlite3"
    records = [
        {"cve": "CVE-1", "affected_product": "opencti", "affected_version": None, "cvss_score": 9.0, "epss": 0.2, "kev": False, "source": "nvd"},
        {"cve": "CVE-2", "affected_product": "opencti", "affected_version": None, "cvss_score": 7.0, "epss": 0.1, "kev": True, "source": "nvd"},
        {"cve": "CVE-3", "affected_product": "other", "affected_version": None, "cvss_score": 10.0, "epss": 1.0, "kev": True, "source": "nvd"},
    ]

    assert rebuild_local_index(records, path, "v1") == 3
    matches = query_local_candidates(path, "opencti", None, 1)

    assert matches is not None
    assert [row.cve for row in matches] == ["CVE-2"]


def test_local_index_is_optional_and_rebuild_invalidates_lru(tmp_path: Path):
    path = tmp_path / "cve.sqlite3"
    assert query_local_candidates(path, "nginx", None, 10) is None

    rebuild_local_index([{"cve": "CVE-A", "affected_product": "nginx", "kev": False}], path, "v1")
    assert [row.cve for row in query_local_candidates(path, "nginx", None, 10) or []] == ["CVE-A"]

    rebuild_local_index([{"cve": "CVE-B", "affected_product": "nginx", "kev": False}], path, "v2")
    assert [row.cve for row in query_local_candidates(path, "nginx", None, 10) or []] == ["CVE-B"]

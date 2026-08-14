"""Rebuildable SQLite CVE read-model with process-local LRU lookup."""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class LocalCveCandidate:
    cve: str
    cvss: float | None
    cvss_score: float | None
    severity: str | None
    epss: float | None
    kev: bool
    affected_vendor: str | None
    affected_product: str | None
    affected_version: str | None
    source: str | None


SCHEMA = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE cve_candidates (
    cve TEXT PRIMARY KEY,
    cvss_score REAL,
    severity TEXT,
    epss REAL,
    kev INTEGER NOT NULL DEFAULT 0,
    affected_vendor TEXT,
    affected_product TEXT,
    affected_version TEXT,
    source TEXT,
    last_synced_at TEXT
);
CREATE INDEX idx_cve_local_product_version
ON cve_candidates(lower(affected_product), lower(coalesce(affected_version, '')));
"""


def rebuild_local_index(records: Iterable[dict[str, Any]], path: str | Path, dataset_version: str) -> int:
    """Atomically replace the local read-model; PostgreSQL remains authoritative."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    rows = list(records)
    with closing(sqlite3.connect(temporary)) as db:
        with db:
            db.executescript(SCHEMA)
            db.execute("INSERT INTO metadata(key, value) VALUES ('dataset_version', ?)", (dataset_version,))
            db.executemany(
            """
            INSERT INTO cve_candidates (
                cve, cvss_score, severity, epss, kev, affected_vendor,
                affected_product, affected_version, source, last_synced_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                [
                    (
                        row.get("cve"), row.get("cvss_score") if row.get("cvss_score") is not None else row.get("cvss"),
                        row.get("severity"), row.get("epss"), int(bool(row.get("kev"))),
                        row.get("affected_vendor"), row.get("affected_product"), row.get("affected_version"),
                        row.get("source"), str(row.get("last_synced_at") or ""),
                    )
                    for row in rows if row.get("cve")
                ],
            )
    os.replace(temporary, target)
    _query_cached.cache_clear()
    return len(rows)


def query_local_candidates(path: str | Path, product: str, version: str | None, limit: int) -> list[LocalCveCandidate] | None:
    target = Path(path)
    if not target.is_file():
        return None
    try:
        return list(_query_cached(str(target.resolve()), target.stat().st_mtime_ns, product.lower(), (version or "").lower(), limit))
    except (OSError, sqlite3.Error):
        return None


@lru_cache(maxsize=512)
def _query_cached(path: str, mtime_ns: int, product: str, version: str, limit: int) -> tuple[LocalCveCandidate, ...]:
    del mtime_ns  # cache invalidation key only
    version_clause = "lower(coalesce(affected_version, '')) = ?" if version else "coalesce(affected_version, '') IN ('', '*')"
    parameters: list[Any] = [product]
    if version:
        parameters.append(version)
    parameters.append(limit)
    sql = f"""
        SELECT cve, cvss_score, severity, epss, kev, affected_vendor,
               affected_product, affected_version, source
        FROM cve_candidates
        WHERE lower(affected_product) = ? AND {version_clause}
        ORDER BY kev DESC, coalesce(cvss_score, 0) DESC, coalesce(epss, 0) DESC, cve
        LIMIT ?
    """
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
        rows = db.execute(sql, parameters).fetchall()
    return tuple(
        LocalCveCandidate(
            cve=row[0], cvss=row[1], cvss_score=row[1], severity=row[2], epss=row[3], kev=bool(row[4]),
            affected_vendor=row[5], affected_product=row[6], affected_version=row[7], source=row[8],
        )
        for row in rows
    )

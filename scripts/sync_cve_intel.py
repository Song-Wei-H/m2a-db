from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
DESCRIPTION_LIMIT = 1000


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def truncate_description(value: str | None) -> str | None:
    if value is None:
        return None
    return value[:DESCRIPTION_LIMIT]


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def clean_cpe_value(value: str | None) -> str | None:
    if value in (None, "", "*", "-"):
        return None
    return value


def parse_cpe23_uri(cpe: str | None) -> dict[str, str | None]:
    if not cpe:
        return {"vendor": None, "product": None, "version": None}
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return {"vendor": None, "product": None, "version": None}
    return {
        "vendor": clean_cpe_value(parts[3]),
        "product": clean_cpe_value(parts[4]),
        "version": clean_cpe_value(parts[5]),
    }


def extract_cvss(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        cvss_data = rows[0].get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or rows[0].get("baseSeverity")
        return (float(score) if score is not None else None, severity.lower() if severity else None)
    return None, None


def extract_primary_cpe(cve: dict[str, Any]) -> dict[str, str | None]:
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for cpe_match in node.get("cpeMatch") or []:
                if not cpe_match.get("vulnerable", True):
                    continue
                parsed = parse_cpe23_uri(cpe_match.get("criteria") or cpe_match.get("cpe23Uri"))
                if parsed["vendor"] and parsed["product"]:
                    return parsed
    return {"vendor": None, "product": None, "version": None}


def parse_nvd_payload(payload: dict[str, Any], *, limit: int | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions") or []
        description = next(
            (row.get("value") for row in descriptions if row.get("lang") == "en"),
            descriptions[0].get("value") if descriptions else None,
        )
        cvss_score, severity = extract_cvss(cve)
        cpe = extract_primary_cpe(cve)
        records.append(
            {
                "cve": cve_id,
                "description": truncate_description(description),
                "cvss_score": cvss_score,
                "severity": severity,
                "epss": None,
                "kev": False,
                "affected_vendor": cpe["vendor"],
                "affected_product": cpe["product"],
                "affected_version": cpe["version"],
                "published_at": parse_datetime(cve.get("published")),
                "updated_at": parse_datetime(cve.get("lastModified")),
                "source": "nvd",
                "last_synced_at": _now(),
            }
        )
        if limit and len(records) >= limit:
            break
    return records


def parse_kev_payload(payload: dict[str, Any]) -> set[str]:
    return {
        row["cveID"]
        for row in payload.get("vulnerabilities") or []
        if isinstance(row, dict) and row.get("cveID")
    }


def parse_epss_payload(payload: dict[str, Any]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for row in payload.get("data") or []:
        cve = row.get("cve")
        epss = row.get("epss")
        if cve and epss is not None:
            scores[cve] = float(epss)
    return scores


def apply_kev_epss(records: list[dict[str, Any]], kev: set[str], epss: dict[str, float]) -> list[dict[str, Any]]:
    for record in records:
        record["kev"] = record["cve"] in kev
        if record["cve"] in epss:
            record["epss"] = epss[record["cve"]]
    return records


def fetch_json(url: str, *, timeout: float = 30.0) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "m2a-db-cve-sync/1.0"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def build_nvd_url(*, since: str | None, limit: int | None) -> str:
    params: dict[str, str] = {}
    if limit:
        params["resultsPerPage"] = str(limit)
    if since:
        start = f"{since}T00:00:00.000Z"
        end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        params["lastModStartDate"] = start
        params["lastModEndDate"] = end
    return f"{NVD_API_URL}?{urlencode(params)}" if params else NVD_API_URL


async def upsert_cve_records(records: list[dict[str, Any]]) -> int:
    from app.database import async_session

    if not records:
        return 0

    stmt = text(
        """
        INSERT INTO cve_enrichment (
            cve, description, cvss, cvss_score, severity, epss, kev,
            affected_vendor, affected_product, affected_version,
            published_at, updated_at, source, last_synced_at
        )
        VALUES (
            :cve, :description, :cvss_score, :cvss_score, :severity, :epss, :kev,
            :affected_vendor, :affected_product, :affected_version,
            :published_at, :updated_at, :source, :last_synced_at
        )
        ON CONFLICT (cve) DO UPDATE SET
            description = EXCLUDED.description,
            cvss = EXCLUDED.cvss,
            cvss_score = EXCLUDED.cvss_score,
            severity = EXCLUDED.severity,
            epss = EXCLUDED.epss,
            kev = EXCLUDED.kev,
            affected_vendor = EXCLUDED.affected_vendor,
            affected_product = EXCLUDED.affected_product,
            affected_version = EXCLUDED.affected_version,
            published_at = EXCLUDED.published_at,
            updated_at = EXCLUDED.updated_at,
            source = EXCLUDED.source,
            last_synced_at = EXCLUDED.last_synced_at
        """
    )
    async with async_session() as session:
        for record in records:
            await session.execute(stmt, record)
        await session.commit()
    return len(records)


def load_records_from_file(path: Path, *, limit: int | None = None) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return parse_nvd_payload(payload, limit=limit)


async def sync_nvd(*, since: str | None, limit: int | None, dry_run: bool) -> int:
    nvd_payload = fetch_json(build_nvd_url(since=since, limit=limit))
    records = parse_nvd_payload(nvd_payload, limit=limit)
    try:
        kev_ids = parse_kev_payload(fetch_json(CISA_KEV_URL))
    except (OSError, URLError, json.JSONDecodeError, TimeoutError) as exc:
        print(f"warning: KEV sync skipped: {exc}", file=sys.stderr)
        kev_ids = set()
    try:
        epss_scores = parse_epss_payload(fetch_json(EPSS_API_URL))
    except (OSError, URLError, json.JSONDecodeError, TimeoutError) as exc:
        print(f"warning: EPSS sync skipped: {exc}", file=sys.stderr)
        epss_scores = {}

    apply_kev_epss(records, kev_ids, epss_scores)
    if dry_run:
        print(json.dumps(records[: min(len(records), 5)], default=str, indent=2))
        return len(records)
    return await upsert_cve_records(records)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline sync compact CVE intelligence into PostgreSQL.")
    parser.add_argument("--since", help="Sync CVEs modified since YYYY-MM-DD.")
    parser.add_argument("--limit", type=int, help="Maximum NVD records to fetch.")
    parser.add_argument("--source", choices=["nvd"], default="nvd")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-raw-cache", action="store_true", default=True)
    parser.add_argument("--sample-file", type=Path, help="Load an NVD-like JSON fixture instead of calling external APIs.")
    return parser.parse_args(argv)


async def async_main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.sample_file:
            records = load_records_from_file(args.sample_file, limit=args.limit)
            count = len(records) if args.dry_run else await upsert_cve_records(records)
        else:
            count = await sync_nvd(since=args.since, limit=args.limit, dry_run=args.dry_run)
        print(f"synced_records={count}")
        return 0
    except Exception as exc:
        print(f"error: CVE intel sync failed: {exc}", file=sys.stderr)
        return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(async_main(argv))


if __name__ == "__main__":
    raise SystemExit(main())

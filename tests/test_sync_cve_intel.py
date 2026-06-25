import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.sync_cve_intel import (
    DESCRIPTION_LIMIT,
    apply_kev_epss,
    async_main,
    parse_cpe23_uri,
    parse_epss_payload,
    parse_kev_payload,
    parse_nvd_payload,
    truncate_description,
)


def test_cve_sample_json_can_be_parsed_into_slim_records():
    payload = json.loads(Path("data/cve_sample.json").read_text(encoding="utf-8"))

    records = parse_nvd_payload(payload)

    assert records[0]["cve"] == "CVE-2024-NGINX-0001"
    assert records[0]["affected_product"] == "nginx"
    assert records[0]["affected_version"] == "1.25.5"
    assert records[0]["cvss_score"] == 9.8
    assert records[0]["severity"] == "critical"
    assert records[1]["affected_product"] == "opencti"
    assert records[1]["affected_version"] is None


def test_sync_parser_keeps_only_compact_fields_and_no_raw_json():
    payload = json.loads(Path("data/cve_sample.json").read_text(encoding="utf-8"))

    record = parse_nvd_payload(payload, limit=1)[0]

    assert "raw" not in record
    assert "references" not in record
    assert "configurations" not in record
    assert set(record) == {
        "cve",
        "description",
        "cvss_score",
        "severity",
        "epss",
        "kev",
        "affected_vendor",
        "affected_product",
        "affected_version",
        "published_at",
        "updated_at",
        "source",
        "last_synced_at",
    }


def test_description_is_truncated_to_1000_characters():
    description = "A" * 1200

    assert len(truncate_description(description)) == DESCRIPTION_LIMIT


def test_parse_cpe23_uri_extracts_vendor_product_version():
    parsed = parse_cpe23_uri("cpe:2.3:a:nginx:nginx:1.25.5:*:*:*:*:*:*:*")

    assert parsed == {"vendor": "nginx", "product": "nginx", "version": "1.25.5"}


def test_kev_and_epss_payloads_update_slim_records():
    records = [{"cve": "CVE-2024-NGINX-0001", "kev": False, "epss": None}]
    kev_ids = parse_kev_payload({"vulnerabilities": [{"cveID": "CVE-2024-NGINX-0001"}]})
    epss_scores = parse_epss_payload({"data": [{"cve": "CVE-2024-NGINX-0001", "epss": "0.91"}]})

    updated = apply_kev_epss(records, kev_ids, epss_scores)

    assert updated[0]["kev"] is True
    assert updated[0]["epss"] == 0.91


@pytest.mark.asyncio
async def test_sync_script_external_api_failure_exits_zero_without_network():
    with patch("scripts.sync_cve_intel.fetch_json", side_effect=RuntimeError("network down")):
        exit_code = await async_main(["--source", "nvd", "--limit", "1"])

    assert exit_code == 0


@pytest.mark.asyncio
async def test_sync_script_sample_dry_run_does_not_touch_database():
    with patch("scripts.sync_cve_intel.upsert_cve_records") as upsert:
        exit_code = await async_main(["--sample-file", "data/cve_sample.json", "--dry-run"])

    assert exit_code == 0
    upsert.assert_not_called()

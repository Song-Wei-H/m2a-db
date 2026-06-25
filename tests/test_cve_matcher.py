from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models import CveEnrichment, PortCveMatch, TargetCveMatch
from worker.cve_matcher import extract_cpe_evidence, match_cves_for_target, parse_cpe


class FakeExecuteResult:
    def __init__(self, value=None, rows=None):
        self.value = value
        self.rows = rows or []

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.rows


def make_cve(
    cve="CVE-2024-NGINX-0001",
    product="nginx",
    version="1.25.5",
    cvss_score=9.8,
    severity="critical",
    epss=0.72,
    kev=False,
):
    return CveEnrichment(
        cve=cve,
        affected_vendor=product,
        affected_product=product,
        affected_version=version,
        cvss_score=cvss_score,
        severity=severity,
        epss=epss,
        kev=kev,
        source="nvd",
    )


def make_session(candidates=None, existing=None):
    session = MagicMock()
    session.add = MagicMock()
    session.execute = AsyncMock(
        side_effect=[
            FakeExecuteResult(rows=candidates or []),
            FakeExecuteResult(value=existing),
        ]
    )
    return session


def test_parse_cpe_extracts_vendor_product_version():
    parsed = parse_cpe("cpe:2.3:a:nginx:nginx:1.25.5:*:*:*:*:*:*:*")

    assert parsed.vendor == "nginx"
    assert parsed.product == "nginx"
    assert parsed.version == "1.25.5"


def test_extract_cpe_evidence_supports_top_level_and_entries():
    evidence = extract_cpe_evidence(
        {
            "cpe": [{"cpe": "cpe:2.3:a:citeum:opencti:*:*:*:*:*:*:*:*"}],
            "entries": [
                {
                    "cpe": [
                        {
                            "cpe": "cpe:2.3:a:matrix:element:*:*:*:*:*:*:*:*",
                            "vendor": "matrix",
                            "product": "element",
                        }
                    ]
                }
            ],
            "webserver": "nginx",
            "technologies": ["HSTS", "Nginx"],
        }
    )

    assert ("citeum", "opencti", None, "cpe") in {
        (item.vendor, item.product, item.version, item.source) for item in evidence
    }
    assert ("matrix", "element", None, "cpe") in {
        (item.vendor, item.product, item.version, item.source) for item in evidence
    }
    assert ("nginx", "nginx", None, "technology") in {
        (item.vendor, item.product, item.version, item.source) for item in evidence
    }


@pytest.mark.asyncio
async def test_exact_cpe_version_match_inserts_high_confidence_row():
    session = make_session(candidates=[make_cve()])

    matches = await match_cves_for_target(
        session,
        target_id=18,
        open_port_id=443,
        cpe="cpe:2.3:a:nginx:nginx:1.25.5:*:*:*:*:*:*:*",
    )

    inserted = session.add.call_args.args[0]
    assert isinstance(inserted, PortCveMatch)
    assert inserted.target_id == 18
    assert inserted.open_port_id == 443
    assert inserted.cve_id == "CVE-2024-NGINX-0001"
    assert inserted.match_type == "exact_cpe_version"
    assert inserted.match_confidence == 1.0
    assert matches[0]["inserted"] is True


@pytest.mark.asyncio
async def test_product_only_cpe_is_candidate_with_capped_confidence():
    session = make_session(
        candidates=[
            make_cve(
                cve="CVE-2024-OPENCTI-0001",
                product="opencti",
                version=None,
                cvss_score=6.5,
                severity="medium",
            )
        ]
    )

    matches = await match_cves_for_target(
        session,
        target_id=18,
        open_port_id=443,
        parsed_output={"cpe": [{"cpe": "cpe:2.3:a:citeum:opencti:*:*:*:*:*:*:*:*"}]},
    )

    inserted = session.add.call_args.args[0]
    assert inserted.match_type == "cpe_product_only"
    assert inserted.match_confidence <= 0.6
    assert inserted.version is None
    assert "version unknown" in matches[0]["reason"]


@pytest.mark.asyncio
async def test_entries_cpe_product_only_creates_capped_candidate_row():
    session = make_session(
        candidates=[
            make_cve(
                cve="CVE-2024-ELEMENT-0001",
                product="element",
                version="*",
                cvss_score=5.3,
                severity="medium",
            )
        ]
    )

    matches = await match_cves_for_target(
        session,
        target_id=18,
        open_port_id=443,
        parsed_output={
            "entries": [
                {
                    "cpe": [
                        {
                            "cpe": "cpe:2.3:a:matrix:element:*:*:*:*:*:*:*:*",
                            "vendor": "matrix",
                            "product": "element",
                        }
                    ]
                }
            ]
        },
    )

    inserted = session.add.call_args.args[0]
    assert inserted.match_type == "cpe_product_only"
    assert inserted.match_confidence <= 0.6
    assert inserted.version is None
    assert matches[0]["cve_id"] == "CVE-2024-ELEMENT-0001"


@pytest.mark.asyncio
async def test_technology_only_does_not_insert_or_return_cve_match_rows():
    session = make_session()

    matches = await match_cves_for_target(
        session,
        target_id=18,
        open_port_id=443,
        parsed_output={"webserver": "nginx", "technologies": ["Nginx"]},
    )

    session.add.assert_not_called()
    assert matches == []


@pytest.mark.asyncio
async def test_duplicate_cve_match_is_not_inserted_again():
    existing = PortCveMatch(
        target_id=18,
        open_port_id=443,
        cve_id="CVE-2024-NGINX-0001",
        product="nginx",
        version="1.25.5",
        match_type="exact_cpe_version",
    )
    session = make_session(candidates=[make_cve()], existing=existing)

    matches = await match_cves_for_target(
        session,
        target_id=18,
        open_port_id=443,
        cpe="cpe:2.3:a:nginx:nginx:1.25.5:*:*:*:*:*:*:*",
    )

    session.add.assert_not_called()
    assert matches[0]["inserted"] is False


@pytest.mark.asyncio
async def test_target_level_match_is_used_when_open_port_id_is_missing():
    session = make_session(candidates=[make_cve()])

    matches = await match_cves_for_target(
        session,
        target_id=18,
        open_port_id=None,
        cpe="cpe:2.3:a:nginx:nginx:1.25.5:*:*:*:*:*:*:*",
    )

    inserted = session.add.call_args.args[0]
    assert isinstance(inserted, TargetCveMatch)
    assert inserted.target_id == 18
    assert inserted.cve_id == "CVE-2024-NGINX-0001"
    assert matches[0]["inserted"] is True

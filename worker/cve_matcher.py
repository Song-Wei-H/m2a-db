from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import PortCveMatch


@dataclass(frozen=True)
class CpeEvidence:
    vendor: str
    product: str
    version: str | None
    cpe: str | None
    source: str


DETERMINISTIC_CVE_DATA: dict[tuple[str, str], list[dict[str, Any]]] = {
    ("nginx", "nginx"): [
        {"cve_id": "CVE-2024-NGINX-0001", "cvss": 8.8, "epss": 0.72, "kev": False},
    ],
    ("citeum", "opencti"): [
        {"cve_id": "CVE-2024-OPENCTI-0001", "cvss": 8.8, "epss": 0.31, "kev": False},
    ],
    ("matrix", "element"): [
        {"cve_id": "CVE-2024-ELEMENT-0001", "cvss": 6.5, "epss": 0.08, "kev": False},
    ],
}


def _clean(value: Any) -> str | None:
    if value in (None, "", "*", "-"):
        return None
    return str(value).strip().lower() or None


def parse_cpe(cpe: str | None) -> CpeEvidence | None:
    if not cpe or not isinstance(cpe, str):
        return None

    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None

    vendor = _clean(parts[3])
    product = _clean(parts[4])
    if not vendor or not product:
        return None

    return CpeEvidence(
        vendor=vendor,
        product=product,
        version=_clean(parts[5]),
        cpe=cpe,
        source="cpe",
    )


def extract_cpe_evidence(parsed_output: dict[str, Any] | None) -> list[CpeEvidence]:
    if not isinstance(parsed_output, dict):
        return []

    evidence: list[CpeEvidence] = []

    def add_cpe_item(item: Any) -> None:
        if isinstance(item, str):
            parsed = parse_cpe(item)
            if parsed:
                evidence.append(parsed)
            return
        if not isinstance(item, dict):
            return

        parsed = parse_cpe(item.get("cpe"))
        vendor = _clean(item.get("vendor")) or (parsed.vendor if parsed else None)
        product = _clean(item.get("product")) or (parsed.product if parsed else None)
        version = _clean(item.get("version")) or (parsed.version if parsed else None)
        if vendor and product:
            evidence.append(
                CpeEvidence(
                    vendor=vendor,
                    product=product,
                    version=version,
                    cpe=item.get("cpe") or (parsed.cpe if parsed else None),
                    source="cpe",
                )
            )

    for item in parsed_output.get("cpe") or []:
        add_cpe_item(item)

    for entry in parsed_output.get("entries") or []:
        if isinstance(entry, dict):
            for item in entry.get("cpe") or []:
                add_cpe_item(item)

    webserver = _clean(parsed_output.get("webserver"))
    if webserver:
        evidence.append(CpeEvidence(vendor=webserver, product=webserver, version=None, cpe=None, source="technology"))

    for technology in parsed_output.get("technologies") or []:
        name = _clean(technology)
        if name:
            evidence.append(CpeEvidence(vendor=name, product=name, version=None, cpe=None, source="technology"))

    deduped: list[CpeEvidence] = []
    seen = set()
    for item in evidence:
        key = (item.vendor, item.product, item.version, item.cpe, item.source)
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _match_type(evidence: CpeEvidence) -> tuple[str, float]:
    if evidence.cpe and evidence.version:
        return "exact_cpe_version", 1.0
    if evidence.cpe:
        return "cpe_product_only", 0.6
    return "technology_only", 0.3


def _candidate_rows(evidence: CpeEvidence) -> list[dict[str, Any]]:
    return DETERMINISTIC_CVE_DATA.get((evidence.vendor, evidence.product), [])


async def _already_exists(
    session: AsyncSession,
    *,
    target_id: int,
    open_port_id: int,
    cve_id: str,
    match_type: str,
) -> bool:
    result = await session.execute(
        select(PortCveMatch)
        .where(
            PortCveMatch.target_id == target_id,
            PortCveMatch.open_port_id == open_port_id,
            PortCveMatch.cve_id == cve_id,
            PortCveMatch.match_type == match_type,
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def match_cves_for_target(
    session: AsyncSession,
    *,
    target_id: int,
    open_port_id: int | None,
    parsed_output: dict[str, Any] | None = None,
    cpe: str | None = None,
) -> list[dict[str, Any]]:
    if open_port_id is None:
        return []

    evidence_items = extract_cpe_evidence(parsed_output)
    parsed_cpe = parse_cpe(cpe)
    if parsed_cpe:
        evidence_items.append(parsed_cpe)

    matches: list[dict[str, Any]] = []
    for evidence in evidence_items:
        match_type, confidence = _match_type(evidence)
        candidates = _candidate_rows(evidence)

        if match_type == "technology_only":
            continue

        for candidate in candidates:
            row_data = {
                "target_id": target_id,
                "open_port_id": open_port_id,
                "cve_id": candidate["cve_id"],
                "product": evidence.product,
                "version": evidence.version,
                "cvss": candidate["cvss"],
                "epss": candidate["epss"],
                "kev": candidate["kev"],
                "match_type": match_type,
                "match_confidence": confidence,
                "source": evidence.cpe or "deterministic_mock_cve_feed",
            }
            inserted = False
            if not await _already_exists(
                session,
                target_id=target_id,
                open_port_id=open_port_id,
                cve_id=candidate["cve_id"],
                match_type=match_type,
            ):
                session.add(PortCveMatch(**row_data))
                inserted = True

            matches.append(
                {
                    **row_data,
                    "inserted": inserted,
                    "reason": (
                        "Exact CPE version match."
                        if match_type == "exact_cpe_version"
                        else "CPE product-only candidate; version unknown, confidence capped."
                    ),
                }
            )

    return matches

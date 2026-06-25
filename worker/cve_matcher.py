from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CveEnrichment, PortCveMatch, TargetCveMatch


@dataclass(frozen=True)
class CpeEvidence:
    vendor: str
    product: str
    version: str | None
    cpe: str | None
    source: str


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


def _candidate_version(value: Any) -> str | None:
    cleaned = _clean(value)
    if cleaned in (None, "*"):
        return None
    return cleaned


async def _candidate_rows(session: AsyncSession, evidence: CpeEvidence) -> list[CveEnrichment]:
    query = select(CveEnrichment).where(
        func.lower(CveEnrichment.affected_product) == evidence.product,
    )
    if evidence.version:
        query = query.where(func.lower(CveEnrichment.affected_version) == evidence.version)
    else:
        query = query.where(
            (CveEnrichment.affected_version.is_(None))
            | (CveEnrichment.affected_version == "")
            | (CveEnrichment.affected_version == "*")
        )
    result = await session.execute(query.order_by(CveEnrichment.cve))
    return list(result.scalars().all())


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


async def _target_match_exists(
    session: AsyncSession,
    *,
    target_id: int,
    cve_id: str,
    match_type: str,
) -> bool:
    result = await session.execute(
        select(TargetCveMatch)
        .where(
            TargetCveMatch.target_id == target_id,
            TargetCveMatch.cve_id == cve_id,
            TargetCveMatch.match_type == match_type,
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
    evidence_items = extract_cpe_evidence(parsed_output)
    parsed_cpe = parse_cpe(cpe)
    if parsed_cpe:
        evidence_items.append(parsed_cpe)

    matches: list[dict[str, Any]] = []
    for evidence in evidence_items:
        match_type, confidence = _match_type(evidence)

        if match_type == "technology_only":
            continue

        candidates = await _candidate_rows(session, evidence)

        for candidate in candidates:
            cve_id = candidate.cve
            cvss_score = candidate.cvss_score if candidate.cvss_score is not None else candidate.cvss
            affected_version = _candidate_version(candidate.affected_version)
            match_reason = (
                "Exact product and version match from local cve_enrichment."
                if match_type == "exact_cpe_version"
                else "Product-only candidate from local cve_enrichment; version unknown, confidence capped."
            )
            row_data = {
                "target_id": target_id,
                "cve_id": cve_id,
                "cve": cve_id,
                "product": evidence.product,
                "version": evidence.version,
                "cvss": cvss_score,
                "cvss_score": cvss_score,
                "severity": candidate.severity,
                "epss": candidate.epss,
                "kev": bool(candidate.kev),
                "match_type": match_type,
                "match_confidence": confidence,
                "match_reason": match_reason,
                "source": candidate.source or "local_cve_enrichment",
                "affected_vendor": candidate.affected_vendor,
                "affected_product": candidate.affected_product,
                "affected_version": affected_version,
            }
            inserted = False
            if open_port_id is not None:
                port_row_data = {**row_data, "open_port_id": open_port_id}
                if not await _already_exists(
                    session,
                    target_id=target_id,
                    open_port_id=open_port_id,
                    cve_id=cve_id,
                    match_type=match_type,
                ):
                    session.add(PortCveMatch(**port_row_data))
                    inserted = True
                output_data = port_row_data
            else:
                if not await _target_match_exists(
                    session,
                    target_id=target_id,
                    cve_id=cve_id,
                    match_type=match_type,
                ):
                    session.add(TargetCveMatch(**row_data))
                    inserted = True
                output_data = row_data

            matches.append(
                {
                    **output_data,
                    "inserted": inserted,
                    "reason": match_reason,
                }
            )

    return matches

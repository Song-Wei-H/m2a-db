# pyright: reportAttributeAccessIssue=false
"""CVE enrichment scoring utilities.

MVP 版：
- 不在 Kali 查 CVE
- 由 Windows / Orchestrator 寫入 cve_enrichment
- 本模組只讀 DB 既有 PortCveMatch
- 根據 CVSS / EPSS / KEV / match_confidence 計算風險加權
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import PortCveMatch


@dataclass(frozen=True)
class CveRiskSummary:
    total_score: float
    max_cvss: float | None
    max_epss: float | None
    has_kev: bool
    best_cve: str | None
    cve_count: int
    best_match_confidence: float | None
    best_match_type: str | None


def clamp_score(value: float, *, minimum: float = 0.0, maximum: float = 10.0) -> float:
    return max(minimum, min(value, maximum))


def normalize_confidence(match_confidence: float | None) -> float:
    if match_confidence is None:
        return 0.10

    return clamp_score(float(match_confidence), minimum=0.0, maximum=1.0)


def is_high_confidence_version_match(row: PortCveMatch) -> bool:
    return (
        row.match_type == "exact_cpe_version"
        and normalize_confidence(row.match_confidence) >= 0.85
        and row.version not in (None, "", "*")
    )


def row_cvss(row: PortCveMatch) -> float | None:
    return row.cvss_score if getattr(row, "cvss_score", None) is not None else row.cvss


def score_single_cve(
    *,
    cvss: float | None,
    epss: float | None,
    kev: bool,
    match_confidence: float | None,
) -> float:
    confidence = normalize_confidence(match_confidence)
    score = 0.0

    if cvss is not None:
        if cvss >= 9.0:
            score += 4.0
        elif cvss >= 7.0:
            score += 3.0
        elif cvss >= 4.0:
            score += 1.5

    # EPSS 只有在匹配可信度夠高時才加權，避免 product-only 誤判被放大。
    if epss is not None and confidence >= 0.70:
        if epss >= 0.70:
            score += 3.0
        elif epss >= 0.30:
            score += 2.0
        elif epss >= 0.05:
            score += 1.0

    # KEV 只有 version_range / exact 類型可信度時才重加權。
    if kev and confidence >= 0.85:
        score += 4.0

    return clamp_score(score * confidence)


def decide_action_from_cve_score(
    *,
    base_action: str,
    base_next_tool: str | None,
    cve_score: float,
    has_kev: bool,
    max_cvss: float | None,
) -> tuple[str, str | None]:
    if has_kev and max_cvss is not None and max_cvss >= 9.0:
        if cve_score >= 7.0:
            return "remediate", None

        return "verify", "nuclei_safe"

    if cve_score >= 7.0:
        return "verify", "nuclei_safe"

    if cve_score >= 4.0:
        return "verify", "nuclei_safe"

    return base_action, base_next_tool


async def summarize_cve_risk(
    db: AsyncSession,
    *,
    target_id: int,
    open_port_id: int,
) -> CveRiskSummary:
    rows = list(
        (
            await db.execute(
                select(PortCveMatch)
                .where(
                    PortCveMatch.target_id == target_id,
                    PortCveMatch.open_port_id == open_port_id,
                )
                .order_by(PortCveMatch.id.desc())
            )
        )
        .scalars()
        .all()
    )

    if not rows:
        return CveRiskSummary(
            total_score=0.0,
            max_cvss=None,
            max_epss=None,
            has_kev=False,
            best_cve=None,
            cve_count=0,
            best_match_confidence=None,
            best_match_type=None,
        )

    best_score = 0.0
    best_cve: str | None = None
    best_match_confidence: float | None = None
    best_match_type: str | None = None

    total_score = 0.0
    max_cvss: float | None = None
    max_epss: float | None = None
    has_kev = False

    for row in rows:
        item_score = score_single_cve(
            cvss=row_cvss(row),
            epss=row.epss,
            kev=bool(row.kev),
            match_confidence=row.match_confidence,
        )

        total_score += item_score

        if item_score > best_score:
            best_score = item_score
            best_cve = row.cve_id
            best_match_confidence = row.match_confidence
            best_match_type = row.match_type

        current_cvss = row_cvss(row)
        if is_high_confidence_version_match(row) and current_cvss is not None:
            max_cvss = current_cvss if max_cvss is None else max(max_cvss, current_cvss)

        if is_high_confidence_version_match(row) and row.epss is not None:
            max_epss = row.epss if max_epss is None else max(max_epss, row.epss)

        if is_high_confidence_version_match(row) and row.kev:
            has_kev = True

    return CveRiskSummary(
        total_score=clamp_score(total_score),
        max_cvss=max_cvss,
        max_epss=max_epss,
        has_kev=has_kev,
        best_cve=best_cve,
        cve_count=len(rows),
        best_match_confidence=best_match_confidence,
        best_match_type=best_match_type,
    )

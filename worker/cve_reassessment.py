"""Create advisory decisions from version-unverified CVE candidates.

Product-only CPE matches prove that a relevant product is exposed, but do not
prove that its installed version is affected.  They therefore never create an
executable ToolTask or raise the target to a confirmed vulnerability state.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import DecisionScore, OpenPort, PortCveMatch, Target


@dataclass(frozen=True)
class CveCandidateDecision:
    target_id: int
    next_action: str
    next_tool: str
    mitre_phase: str
    mitre_technique: str
    risk_score: float
    confidence: float
    reason: str
    decision_score_id: int | None


def build_cve_candidate_decision(
    *, target_id: int, open_port_id: int | None, candidates: list[PortCveMatch]
) -> dict:
    """Build a non-executable version-verification decision from candidates."""
    candidate_ids = sorted({candidate.cve_id for candidate in candidates})
    confidence = max((float(candidate.match_confidence or 0) for candidate in candidates), default=0.0)
    return {
        "target_id": target_id,
        "open_port_id": open_port_id,
        "risk_score": 0.0,
        "base_risk_score": 0.0,
        "adjusted_risk_score": 0.0,
        "confidence_score": confidence,
        "severity": "info",
        "confidence": confidence,
        "next_action": "verify",
        "next_tool": "version_verification",
        "mitre_phase": None,
        "mitre_technique": None,
        "reason": (
            f"{len(candidate_ids)} product-only CVE candidate(s) require installed-version "
            "verification before vulnerability scoring or remediation."
        ),
        "reasoning": [
            "Product CPE was observed but the installed product version was not observed.",
            "CVE, CVSS, EPSS, and KEV values remain contextual intelligence until version applicability is verified.",
            "No executable ToolTask is created for version_verification.",
        ],
        "input_snapshot": {
            "stage": "cve_candidate_reassessment",
            "candidate_cve_ids": candidate_ids,
            "candidate_count": len(candidate_ids),
            "match_type": "cpe_product_only",
            "human_decision_required": True,
            "requested_decision": "Obtain the installed OpenCTI version through an approved administrative or inventory channel.",
        },
    }


async def reassess_cve_candidates(db: AsyncSession, *, target_id: int) -> CveCandidateDecision:
    """Persist one advisory version-verification decision for current candidates."""
    async with db.begin():
        target = await db.get(Target, target_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"target_id={target_id} not found")

        rows = (
            await db.execute(
                select(PortCveMatch, OpenPort)
                .outerjoin(OpenPort, OpenPort.id == PortCveMatch.open_port_id)
                .where(
                    PortCveMatch.target_id == target_id,
                    PortCveMatch.match_type == "cpe_product_only",
                )
                .order_by(PortCveMatch.open_port_id, PortCveMatch.id)
            )
        ).all()
        candidates = [candidate for candidate, _ in rows]
        if not candidates:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="No product-only CVE candidates are available for reassessment",
            )

        open_port_id = candidates[0].open_port_id
        values = build_cve_candidate_decision(
            target_id=target_id,
            open_port_id=open_port_id,
            candidates=candidates,
        )
        decision = DecisionScore(**values)
        db.add(decision)
        await db.flush()

    return CveCandidateDecision(
        target_id=target_id,
        next_action=decision.next_action,
        next_tool=decision.next_tool or "none",
        mitre_phase=decision.mitre_phase or "none",
        mitre_technique=decision.mitre_technique or "none",
        risk_score=decision.risk_score,
        confidence=decision.confidence or 0.0,
        reason=decision.reason or "",
        decision_score_id=decision.id,
    )

"""Tool Decision Engine — load DB context, score, persist decision."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.tool_catalog import DEPTH_VALIDATION_TOOLS, SAFE_DISCOVERY_TOOLS
from app.tool_task_constants import NOT_REQUIRED, PENDING, PENDING_APPROVAL


def _determine_approval(
    tool_name: str,
    risk_score: float,
    confidence: float,
) -> tuple[bool, str, str | None]:

    if tool_name in SAFE_DISCOVERY_TOOLS:
        return False, NOT_REQUIRED, None

    if tool_name in DEPTH_VALIDATION_TOOLS:
        high_risk = risk_score >= 6.0
        high_confidence = confidence >= 0.8

        if high_risk or high_confidence:
            return (
                True,
                PENDING_APPROVAL,
                "High-risk validation requires human approval",
            )

        return False, NOT_REQUIRED, None

    # Unknown tools require governance review
    return (
        True,
        PENDING_APPROVAL,
        f"Unknown or uncategorized tool requires human approval: {tool_name}",
    )

from app.mitre_rules import (
    FORBIDDEN_TOOLS,
    map_service_to_mitre,
    select_next_tool,
)
from app.security.tool_policy import resolve_template_tool
from app.tool_task_writer import create_tool_task_if_not_exists
from app.models import (
    CveEnrichment,
    DecisionScore,
    OpenPort,
    Target,
    ToolResult,
    ToolTask,
    Vulnerability,
)
from app.scoring import (
    PortContext,
    TargetAssessmentContext,
    VulnContext,
    compute_confidence,
    compute_risk_score,
    decide_next_action,
    pick_focus_port,
    score_vulnerability,
)

logger = logging.getLogger(__name__)


@dataclass
class DecisionResult:
    target_id: int
    next_action: str
    next_tool: str
    mitre_phase: str
    mitre_technique: str
    risk_score: float
    confidence: float
    reason: str
    decision_score_id: int | None = None
    tool_task_id: int | None = None


async def _load_tool_results(db: AsyncSession, target_id: int) -> list[dict]:
    stmt = (
        select(
            ToolResult.id,
            ToolResult.tool_name,
            ToolResult.success,
            ToolResult.risk_level,
            ToolResult.open_port_id,
            OpenPort.port,
        )
        .outerjoin(OpenPort, OpenPort.id == ToolResult.open_port_id)
        .where(ToolResult.target_id == target_id)
    )
    rows = await db.execute(stmt)
    return [
        {
            "id": r.id,
            "tool_name": r.tool_name,
            "success": r.success,
            "risk_level": r.risk_level,
            "open_port_id": r.open_port_id,
            "port": r.port,
        }
        for r in rows.all()
    ]


async def _load_assessment_context(
    db: AsyncSession,
    target_id: int,
) -> TargetAssessmentContext:
    ports_result = await db.execute(
        select(OpenPort).where(
            OpenPort.target_id == target_id,
            OpenPort.state == "open",
        )
    )
    open_ports = [
        PortContext(
            id=p.id,
            port=p.port,
            protocol=p.protocol,
            service=p.service,
            product=p.product,
            version=p.version,
        )
        for p in ports_result.scalars().all()
    ]

    enrichment = aliased(CveEnrichment)
    vuln_stmt = (
        select(Vulnerability, enrichment)
        .outerjoin(enrichment, enrichment.cve == Vulnerability.cve)
        .where(Vulnerability.target_id == target_id)
    )
    vuln_rows = await db.execute(vuln_stmt)
    vulnerabilities = [
        VulnContext(
            cve=v.cve,
            severity=v.severity,
            cvss=v.cvss,
            epss=v.epss,
            kev=bool(v.kev),
            mitre_tactic=v.mitre_tactic,
            mitre_technique=v.mitre_technique,
            enrichment_cvss=e.cvss if e else None,
            enrichment_epss=e.epss if e else None,
            enrichment_kev=bool(e.kev) if e else False,
            enrichment_tactic=e.mitre_tactic if e else None,
            enrichment_technique=e.mitre_technique if e else None,
        )
        for v, e in vuln_rows.all()
    ]

    tool_results = await _load_tool_results(db, target_id)

    return TargetAssessmentContext(
        target_id=target_id,
        open_ports=open_ports,
        vulnerabilities=vulnerabilities,
        tool_results=tool_results,
    )


def _build_reason(
    ctx: TargetAssessmentContext,
    risk_score: float,
    next_action: str,
    next_tool: str,
    focus: PortContext | None,
) -> str:
    parts = [f"risk_score={risk_score}", f"next_action={next_action}"]
    parts.append(f"open_ports={len(ctx.open_ports)}")
    parts.append(f"vulnerabilities={len(ctx.vulnerabilities)}")
    if focus and focus.port:
        parts.append(f"focus_port={focus.port}/{focus.protocol or 'tcp'}")
        if focus.service:
            parts.append(f"service={focus.service}")
    if next_tool != "none":
        parts.append(f"next_tool={next_tool}")
    else:
        parts.append("no safe follow-up tool")
    return "; ".join(parts)


async def run_decision_for_target(
    db: AsyncSession,
    target_id: int,
) -> DecisionResult:
    async with db.begin():
        target = await db.get(Target, target_id)
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"target_id={target_id} not found",
            )

        ctx = await _load_assessment_context(db, target_id)
        risk_score = compute_risk_score(ctx)
        confidence = compute_confidence(ctx)
        focus = pick_focus_port(ctx)

        tool_results = ctx.tool_results
        if focus:
            tool_choice = select_next_tool(focus.port, focus.service, tool_results)
        else:
            tool_choice = select_next_tool(None, None, tool_results)

        next_tool = tool_choice.tool
        if next_tool in FORBIDDEN_TOOLS:
            logger.warning(
                "Blocked forbidden tool %s for target_id=%s",
                next_tool,
                target_id,
            )
            next_tool = "none"

        has_kev = any(v.kev or v.enrichment_kev for v in ctx.vulnerabilities)

        next_action = decide_next_action(
            risk_score,
            next_tool=next_tool,
            vulnerabilities=ctx.vulnerabilities,
        )

        enrichment_tactic = None
        enrichment_technique = None
        if ctx.vulnerabilities:
            top_vuln = max(ctx.vulnerabilities, key=score_vulnerability)
            enrichment_tactic = top_vuln.enrichment_tactic or top_vuln.mitre_tactic
            enrichment_technique = (
                top_vuln.enrichment_technique or top_vuln.mitre_technique
            )

        mitre = map_service_to_mitre(
            focus.service if focus else None,
            focus.port if focus else None,
            kev_present=has_kev,
            enrichment_tactic=enrichment_tactic,
            enrichment_technique=enrichment_technique,
        )

        reason = _build_reason(ctx, risk_score, next_action, next_tool, focus)

        snapshot = {
            "open_ports": [asdict(p) for p in ctx.open_ports],
            "vulnerability_count": len(ctx.vulnerabilities),
            "tool_result_count": len(ctx.tool_results),
            "tool_rationale": tool_choice.rationale,
        }

        decision_row = DecisionScore(
            target_id=target_id,
            open_port_id=focus.id if focus else None,
            risk_score=risk_score,
            next_action=next_action,
            next_tool=next_tool,
            mitre_phase=mitre.phase,
            mitre_technique=mitre.technique,
            confidence=confidence,
            reason=reason,
            input_snapshot=snapshot,
        )
        db.add(decision_row)
        await db.flush()

        tool_task_id: int | None = None

        if next_action in ("continue", "verify") and next_tool != "none":
            approval_required = False
            approval_status = NOT_REQUIRED
            approval_reason = None
            try:
                template_tool = resolve_template_tool(next_tool)

                approval_required, approval_status, approval_reason = (
                    _determine_approval(
                        template_tool,
                        risk_score,
                        confidence,
                    )
                )

            except ValueError as exc:
                logger.warning(
                    "Skipping tool_task for target_id=%s: %s",
                    target_id,
                    exc,
                )
                template_tool = None

            if template_tool:
                task, _ = await create_tool_task_if_not_exists(
                    db,
                    target_id=target_id,
                    open_port_id=focus.id if focus else None,
                    decision_score_id=decision_row.id,
                    tool_name=template_tool,
                    status=PENDING,
                    priority=_task_priority(risk_score),
                    approval_required=approval_required,
                    approval_status=approval_status,
                    approval_reason=approval_reason,
                )

                tool_task_id = task.id if task else None

        return DecisionResult(
            target_id=target_id,
            next_action=next_action,                
            next_tool=next_tool,
            mitre_phase=mitre.phase,
            mitre_technique=mitre.technique,
            risk_score=risk_score,
            confidence=confidence,
            reason=reason,
            decision_score_id=decision_row.id,
            tool_task_id=tool_task_id,
        )


def _task_priority(risk_score: float) -> int:
    if risk_score >= 8.0:
        return 1
    if risk_score >= 6.0:
        return 3
    return 5

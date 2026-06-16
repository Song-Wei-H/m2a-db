"""Worker Analysis Pipeline."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select

from app.database import async_session
from app.models import AutoLoopDecision, DecisionScore, EvidenceConfidence, OpenPort, Target, ToolTask
from worker.confidence_scoring import calculate_confidence
from worker.cve_enrichment import summarize_cve_risk
from worker.evidence_normalizer import normalize_tool_result
from worker.learning_engine import get_learning_feedback, record_learning_feedback
from worker.mitre_mapper import map_to_mitre
from worker.risk_engine_v3 import calculate_risk
from worker.tool_name_normalizer import normalize_tool_name
from worker.auto_loop import get_next_tool_task

__all__ = ["analyze_tool_result_and_generate_task"]

logger = logging.getLogger(__name__)

HTTP_SERVICES = {"http", "https", "http-alt", "www", "ssl/http"}


def _score_open_port(port: OpenPort) -> dict[str, Any]:
    service = (port.service or "").lower()

    if service in HTTP_SERVICES or port.port in (80, 443, 8000, 8080, 8443):
        return {
            "risk_score": 4.0,
            "confidence": 0.85,
            "next_action": "continue",
            "next_tool": "httpx_basic",
            "mitre_phase": "Initial Access",
            "mitre_technique": "T1190",
            "reason": (
                f"HTTP-like service detected on port "
                f"{port.port}/{port.protocol}: {port.service}"
            ),
        }

    if service == "ssh" or port.port == 22:
        return {
            "risk_score": 2.0,
            "confidence": 0.75,
            "next_action": "stop",
            "next_tool": None,
            "mitre_phase": "Lateral Movement",
            "mitre_technique": "T1021",
            "reason": (
                f"SSH service detected on port "
                f"{port.port}/{port.protocol}; ssh-enum is currently disabled."
            ),
        }

    return {
        "risk_score": 1.0,
        "confidence": 0.60,
        "next_action": "stop",
        "next_tool": None,
        "mitre_phase": "Discovery",
        "mitre_technique": None,
        "reason": (
            f"No follow-up tool selected for service "
            f"{port.service} on port {port.port}/{port.protocol}."
        ),
    }


async def _existing_tool_task(
    *,
    db,
    target_id: int,
    open_port_id: int,
    tool_name: str,
) -> ToolTask | None:
    # Normalize the tool name
    normalized_tool_name = normalize_tool_name(tool_name)
    
    # Build the query with proper NULL handling for open_port_id
    query = select(ToolTask).where(
        ToolTask.target_id == target_id,
        ToolTask.tool_name == normalized_tool_name,
        ToolTask.status.in_(["pending", "running", "completed"]),
    )
    
    # Handle NULL values properly for open_port_id
    if open_port_id is not None:
        query = query.where(ToolTask.open_port_id == open_port_id)
    else:
        query = query.where(ToolTask.open_port_id.is_(None))
        
    query = query.order_by(ToolTask.id.desc()).limit(1)
    
    return (await db.execute(query)).scalar_one_or_none()


async def _generate_tasks_from_nmap_open_ports(target_id: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    async with async_session() as db, db.begin():
        target = await db.get(Target, target_id)
        if target is None:
            return [{"generated": False, "reason": "Target not found", "target_id": target_id}]

        ports = list(
            (
                await db.execute(
                    select(OpenPort)
                    .where(OpenPort.target_id == target_id)
                    .order_by(OpenPort.port)
                )
            )
            .scalars()
            .all()
        )

        for port in ports:
            score = _score_open_port(port)

            cve_summary = await summarize_cve_risk(
                db,
                target_id=target_id,
                open_port_id=port.id,
            )

            feedback = await get_learning_feedback(
                db,
                "nmap_service",
            )

            risk_v3 = calculate_risk(
                target_id=target_id,
                open_port_id=port.id,
                service=port.service,
                port=port.port,
                cvss=cve_summary.max_cvss,
                epss=cve_summary.max_epss,
                kev=cve_summary.has_kev,
                tool_name="nmap_service",
                parsed_output={
                    "port": port.port,
                    "service": port.service,
                    "product": port.product,
                    "version": port.version,
                    "cve_summary": {
                        "score": cve_summary.total_score,
                        "best_cve": cve_summary.best_cve,
                        "max_cvss": cve_summary.max_cvss,
                        "max_epss": cve_summary.max_epss,
                        "has_kev": cve_summary.has_kev,
                        "cve_count": cve_summary.cve_count,
                        "best_match_type": cve_summary.best_match_type,
                        "best_match_confidence": cve_summary.best_match_confidence,
                    },
                },
                raw_output="",
                base_confidence=score["confidence"],
                learning_feedback=feedback,
            )

            if cve_summary.cve_count:
                score["reason"] = (
                    f'{score["reason"]} CVE enrichment: '
                    f"best_cve={cve_summary.best_cve}, "
                    f"cve_score={cve_summary.total_score}, "
                    f"max_cvss={cve_summary.max_cvss}, "
                    f"max_epss={cve_summary.max_epss}, "
                    f"kev={cve_summary.has_kev}, "
                    f"match_type={cve_summary.best_match_type}, "
                    f"match_confidence={cve_summary.best_match_confidence}."
                )

            decision = DecisionScore(
                target_id=target_id,
                open_port_id=port.id,

                risk_score=risk_v3.risk_score,
                base_risk_score=risk_v3.base_risk_score,
                adjusted_risk_score=risk_v3.adjusted_risk_score,
                confidence_score=risk_v3.confidence_score,

                learning_adjustment=risk_v3.learning_adjustment,
                runtime_adjustment=risk_v3.runtime_adjustment,
                evidence_adjustment=risk_v3.evidence_adjustment,

                waf_detected=risk_v3.waf_detected,
                tool_blocked=risk_v3.tool_blocked,
                tool_timeout=risk_v3.tool_timeout,

                severity=risk_v3.severity,
                confidence=risk_v3.confidence_score,

                next_action=risk_v3.next_action,
                next_tool=risk_v3.next_tool,

                mitre_phase=score["mitre_phase"],
                mitre_technique=score["mitre_technique"],

                reason="Risk Engine v3 generated learning-adjusted base risk",
                reasoning=risk_v3.reasoning,

                input_snapshot={
                    "stage": "base_risk_v3",
                    "port": port.port,
                    "protocol": port.protocol,
                    "service": port.service,
                    "product": port.product,
                    "version": port.version,
                    "state": port.state,
                    "learning_feedback": feedback,
                    "cve": {
                        "score": cve_summary.total_score,
                        "best_cve": cve_summary.best_cve,
                        "max_cvss": cve_summary.max_cvss,
                        "max_epss": cve_summary.max_epss,
                        "has_kev": cve_summary.has_kev,
                        "cve_count": cve_summary.cve_count,
                        "best_match_type": cve_summary.best_match_type,
                        "best_match_confidence": cve_summary.best_match_confidence,
                    },
                },
            )

            db.add(decision)
            await db.flush()

            next_tool = risk_v3.next_tool

            current_round = target.current_round or 1
            max_round = target.max_round or 5
            if current_round >= max_round:
                db.add(
                    AutoLoopDecision(
                        target_id=target_id,
                        round_number=current_round,
                        stop_reason="max_round_reached",
                        next_tool=next_tool,
                    )
                )
                results.append(
                    {
                        "generated": False,
                        "reason": "max_round_reached",
                        "open_port_id": port.id,
                        "port": port.port,
                        "service": port.service,
                        "decision_score_id": decision.id,
                    }
                )
                continue

            if not next_tool:
                db.add(
                    AutoLoopDecision(
                        target_id=target_id,
                        round_number=current_round,
                        stop_reason="no_next_tool",
                        next_tool=None,
                    )
                )
                results.append(
                    {
                        "generated": False,
                        "reason": "No follow-up tool selected",
                        "open_port_id": port.id,
                        "port": port.port,
                        "service": port.service,
                        "decision_score_id": decision.id,
                    }
                )
                continue

            exists = await _existing_tool_task(
                db=db,
                target_id=target_id,
                open_port_id=port.id,
                tool_name=next_tool,
            )

            if exists:
                db.add(
                    AutoLoopDecision(
                        target_id=target_id,
                        round_number=current_round,
                        stop_reason="duplicate_tool",
                        next_tool=next_tool,
                    )
                )
                results.append(
                    {
                        "generated": False,
                        "reason": "ToolTask already exists",
                        "tool_name": next_tool,
                        "open_port_id": port.id,
                        "port": port.port,
                        "service": port.service,
                        "existing_task_id": exists.id,
                        "decision_score_id": decision.id,
                    }
                )
                continue

            task = ToolTask(
                target_id=target_id,
                open_port_id=port.id,
                tool_name=next_tool,
                status="pending",
                approval_required=False,
                approval_status="not_required",
                priority=50,
                decision_score_id=decision.id,
            )

            db.add(task)
            await db.flush()

            results.append(
                {
                    "generated": True,
                    "tool_name": next_tool,
                    "open_port_id": port.id,
                    "port": port.port,
                    "service": port.service,
                    "task_id": task.id,
                    "decision_score_id": decision.id,
                }
            )

    return results


async def analyze_tool_result_and_generate_task(
    *,
    target_id: int,
    open_port_id: int | None,
    tool_name: str,
    parsed_output: dict[str, Any],
    raw_output: str = "",
    tool_result_id: int | None = None,
    ctx: Any | None = None,
    decision_score_id: int | None = None,
) -> list[dict[str, Any]]:
    """Run the deterministic analysis pipeline and generate governed tasks."""

    if tool_name == "nmap_service":
        return await _generate_tasks_from_nmap_open_ports(target_id)

    results: list[dict[str, Any]] = []

    if tool_name == "nuclei_safe":
        finding_count = int(parsed_output.get("finding_count") or 0)
        nuclei_completed_successfully = (
            parsed_output.get("success") is not False
            and parsed_output.get("parser_success") is not False
            and parsed_output.get("status") != "failed"
        )

        if finding_count == 0 and nuclei_completed_successfully:
            port_row = None
            cve_summary = None

            async with async_session() as db:
                if open_port_id is not None:
                    port_row = await db.get(OpenPort, open_port_id)
                    cve_summary = await summarize_cve_risk(
                        db,
                        target_id=target_id,
                        open_port_id=open_port_id,
                    )

                feedback = await get_learning_feedback(
                    db,
                    tool_name,
                )

            risk_v3 = calculate_risk(
                target_id=target_id,
                open_port_id=open_port_id,
                service=port_row.service if port_row else None,
                port=port_row.port if port_row else None,
                cvss=cve_summary.max_cvss if cve_summary else None,
                epss=cve_summary.max_epss if cve_summary else None,
                kev=cve_summary.has_kev if cve_summary else False,
                tool_name=tool_name,
                parsed_output=parsed_output,
                raw_output=raw_output,
                base_confidence=0.80,
                learning_feedback=feedback,
            )

            async with async_session() as db, db.begin():
                evidence_confidence = EvidenceConfidence(
                    target_id=target_id,
                    open_port_id=open_port_id,
                    decision_score_id=decision_score_id,
                    tool_result_id=tool_result_id,
                    tool_name=tool_name,
                    evidence_type="vulnerability_scan_negative",
                    confidence_score=0.80,
                    confidence_reason="nuclei_safe completed successfully with finding_count=0",
                    supporting_evidence=parsed_output,
                    contradictory_evidence={},
                )
                db.add(evidence_confidence)

                await record_learning_feedback(
                    session=db,
                    decision_id=decision_score_id,
                    tool_result_id=tool_result_id,
                    tool_name=tool_name,
                    service=port_row.service if port_row else None,
                    evidence_type="vulnerability_scan_negative",
                    recommended_action="verify",
                    success=True,
                    was_success=True,
                    confidence_delta=0,
                    learning_score=0.8,
                    reason="nuclei_safe completed with no findings",
                    feedback="nuclei_safe completed successfully but found no vulnerability",
                )

                decision = DecisionScore(
                    target_id=target_id,
                    open_port_id=open_port_id,

                    risk_score=risk_v3.risk_score,
                    base_risk_score=risk_v3.base_risk_score,
                    adjusted_risk_score=risk_v3.adjusted_risk_score,
                    confidence_score=risk_v3.confidence_score,

                    learning_adjustment=risk_v3.learning_adjustment,
                    runtime_adjustment=risk_v3.runtime_adjustment,
                    evidence_adjustment=risk_v3.evidence_adjustment,

                    waf_detected=risk_v3.waf_detected,
                    tool_blocked=risk_v3.tool_blocked,
                    tool_timeout=risk_v3.tool_timeout,

                    severity=risk_v3.severity,
                    confidence=risk_v3.confidence_score,

                    next_action=risk_v3.next_action,
                    next_tool=risk_v3.next_tool,

                    mitre_phase="Initial Access",
                    mitre_technique="T1190",

                    reason="Risk Engine v3 generated negative validation risk",
                    reasoning=risk_v3.reasoning,

                    input_snapshot={
                        "stage": "negative_validation_v3",
                        "tool_name": tool_name,
                        "tool_result_id": tool_result_id,
                        "learning_feedback": feedback,
                        "parsed_output": parsed_output,
                    },
                )

                db.add(decision)
                await db.flush()

                new_decision_score_id = decision.id

            # Create decision result for auto loop
            decision_result = {
                "recommended_tool": risk_v3.next_tool,
                "recommended_action": risk_v3.next_action,
                "decision_score_id": new_decision_score_id,
                "priority": (
                    100 if risk_v3.severity == "critical"
                    else 80 if risk_v3.severity == "high"
                    else 50 if risk_v3.severity == "medium"
                    else 10
                ),
                "requires_approval": risk_v3.next_action
                in {"verify", "remediate"},
                "risk_score": risk_v3.risk_score,
                "risk_factors": {
                    "base_risk_score": risk_v3.base_risk_score,
                    "adjusted_risk_score": risk_v3.adjusted_risk_score,
                    "confidence_score": risk_v3.confidence_score,
                    "learning_adjustment": risk_v3.learning_adjustment,
                    "runtime_adjustment": risk_v3.runtime_adjustment,
                    "evidence_adjustment": risk_v3.evidence_adjustment,
                    "waf_detected": risk_v3.waf_detected,
                    "tool_blocked": risk_v3.tool_blocked,
                    "tool_timeout": risk_v3.tool_timeout,
                },
                "reasoning": risk_v3.reasoning,
            }

            # Integrate auto loop functionality after DecisionScore is created
            task_result = await get_next_tool_task(
                target_id=target_id, open_port_id=open_port_id, decision_result=decision_result
            )

            return [
                {
                    "generated": False,
                    "reason": "nuclei_safe completed with no findings",
                    "tool_result_id": tool_result_id,
                    "decision_score_id": new_decision_score_id,
                    "evidence_type": "vulnerability_scan_negative",
                    "task_result": task_result,
                }
            ]

    evidence_list = normalize_tool_result(
        tool_name=tool_name,
        parsed_output=parsed_output,
        raw_output=raw_output,
        ctx=ctx,
        tool_result_id=tool_result_id,
    )

    if not evidence_list:
        async with async_session() as db, db.begin():
            decision = DecisionScore(
                target_id=target_id,
                open_port_id=open_port_id,
                risk_score=0.0,
                base_risk_score=0.0,
                adjusted_risk_score=0.0,
                confidence_score=0.0,
                learning_adjustment=0.0,
                runtime_adjustment=0.0,
                evidence_adjustment=0.0,
                waf_detected=False,
                tool_blocked=False,
                tool_timeout=False,
                severity="info",
                confidence=0.0,
                next_action="stop",
                next_tool=None,
                mitre_phase=None,
                mitre_technique=None,
                reason=f"{tool_name} produced no normalized evidence; stopping auto loop",
                reasoning=["No normalized evidence was produced by the parser/normalizer"],
                input_snapshot={
                    "stage": "no_normalized_evidence",
                    "tool_name": tool_name,
                    "tool_result_id": tool_result_id,
                    "previous_decision_score_id": decision_score_id,
                    "parsed_output": parsed_output,
                },
            )
            db.add(decision)
            await db.flush()
            new_decision_score_id = decision.id

        task_result = await get_next_tool_task(
            target_id=target_id,
            open_port_id=open_port_id,
            decision_result={
                "recommended_tool": None,
                "recommended_action": "stop",
                "decision_score_id": new_decision_score_id,
                "priority": 0,
                "requires_approval": False,
                "risk_score": 0.0,
                "reasoning": ["No normalized evidence was produced by the parser/normalizer"],
            },
        )

        return [
            {
                "generated": False,
                "reason": "No normalized evidence; stop decision created",
                "tool_result_id": tool_result_id,
                "decision_score_id": new_decision_score_id,
                "task_result": task_result,
            }
        ]

    for evidence in evidence_list:
        mitre_mapping = map_to_mitre(evidence)

        confidence_result = calculate_confidence(
            evidence=evidence,
            mitre_mapping=mitre_mapping,
        )

        details = evidence.get("details") or {}
        cve_summary = None

        async with async_session() as db:
            feedback = await get_learning_feedback(
                db,
                tool_name,
            )
            if open_port_id is not None:
                cve_summary = await summarize_cve_risk(
                    db,
                    target_id=target_id,
                    open_port_id=open_port_id,
                )

        risk_parsed_output = dict(parsed_output)
        if cve_summary is not None:
            risk_parsed_output["cve_summary"] = {
                "score": cve_summary.total_score,
                "best_cve": cve_summary.best_cve,
                "max_cvss": cve_summary.max_cvss,
                "max_epss": cve_summary.max_epss,
                "has_kev": cve_summary.has_kev,
                "cve_count": cve_summary.cve_count,
                "best_match_type": cve_summary.best_match_type,
                "best_match_confidence": cve_summary.best_match_confidence,
            }

        risk_v3 = calculate_risk(
            target_id=target_id,
            open_port_id=open_port_id,
            service=details.get("service") or evidence.get("service"),
            port=details.get("port") or evidence.get("port"),
            cvss=(cve_summary.max_cvss if cve_summary else None) or details.get("cvss") or details.get("cvss_score"),
            epss=(cve_summary.max_epss if cve_summary else None) or details.get("epss") or details.get("epss_score"),
            kev=bool((cve_summary.has_kev if cve_summary else False) or details.get("kev") or details.get("is_kev")),
            tool_name=tool_name,
            parsed_output=risk_parsed_output,
            raw_output=raw_output,
            base_confidence=confidence_result.get("confidence_score", 0.7),
            learning_feedback=feedback,
        )

        decision_result = {
            "recommended_tool": risk_v3.next_tool,
            "recommended_action": risk_v3.next_action,
            "priority": (
                100 if risk_v3.severity == "critical"
                else 80 if risk_v3.severity == "high"
                else 50 if risk_v3.severity == "medium"
                else 10
            ),
            "requires_approval": risk_v3.next_action
            in {"verify", "remediate"},
            "risk_score": risk_v3.risk_score,
            "risk_factors": {
                "base_risk_score": risk_v3.base_risk_score,
                "adjusted_risk_score": risk_v3.adjusted_risk_score,
                "confidence_score": risk_v3.confidence_score,
                "learning_adjustment": risk_v3.learning_adjustment,
                "runtime_adjustment": risk_v3.runtime_adjustment,
                "evidence_adjustment": risk_v3.evidence_adjustment,
                "waf_detected": risk_v3.waf_detected,
                "tool_blocked": risk_v3.tool_blocked,
                "tool_timeout": risk_v3.tool_timeout,
            },
            "reasoning": risk_v3.reasoning,
        }

        evidence_confidence = EvidenceConfidence(
            target_id=target_id,
            open_port_id=open_port_id,
            decision_score_id=decision_score_id,
            tool_result_id=tool_result_id,
            tool_name=tool_name,
            evidence_type=evidence.get("evidence_type"),
            confidence_score=confidence_result.get(
                "confidence_score",
                evidence.get("confidence", 0.0),
            ),
            confidence_reason="Normalized evidence from tool output",
            supporting_evidence=evidence,
            contradictory_evidence={},
        )

        async with async_session() as db, db.begin():
            logger.info(
                "Creating evidence_confidence target=%s tool=%s evidence_type=%s decision_score_id=%s",
                target_id,
                tool_name,
                evidence.get("evidence_type"),
                decision_score_id,
            )

            db.add(evidence_confidence)

            decision = DecisionScore(
                target_id=target_id,
                open_port_id=open_port_id,

                risk_score=risk_v3.risk_score,
                base_risk_score=risk_v3.base_risk_score,
                adjusted_risk_score=risk_v3.adjusted_risk_score,
                confidence_score=risk_v3.confidence_score,

                learning_adjustment=risk_v3.learning_adjustment,
                runtime_adjustment=risk_v3.runtime_adjustment,
                evidence_adjustment=risk_v3.evidence_adjustment,

                waf_detected=risk_v3.waf_detected,
                tool_blocked=risk_v3.tool_blocked,
                tool_timeout=risk_v3.tool_timeout,

                severity=risk_v3.severity,
                confidence=risk_v3.confidence_score,

                next_action=risk_v3.next_action,
                next_tool=risk_v3.next_tool,

                mitre_phase=mitre_mapping.get("attack_phase")
                or mitre_mapping.get("tactic"),
                mitre_technique=mitre_mapping.get("technique_id"),

                reason="Risk Engine v3 generated learning-adjusted risk",
                reasoning=risk_v3.reasoning,

                input_snapshot={
                    "stage": "adjusted_risk_v3",
                    "tool_name": tool_name,
                    "tool_result_id": tool_result_id,
                    "previous_decision_score_id": decision_score_id,
                    "learning_feedback": feedback,
                    "evidence": evidence,
                    "mitre_mapping": mitre_mapping,
                    "confidence_result": confidence_result,
                    "parsed_output": risk_parsed_output,
                },
            )

            db.add(decision)
            await db.flush()

            new_decision_score_id = decision.id
            decision_result["decision_score_id"] = new_decision_score_id

        # Generate the next governed task after the DecisionScore transaction
        # commits; get_next_tool_task uses a separate session and must see the
        # referenced decision row before inserting ToolTask.decision_score_id.
        task_result = await get_next_tool_task(
            target_id=target_id, open_port_id=open_port_id, decision_result=decision_result
        )

        results.append(
            {
                "evidence": evidence,
                "mitre_mapping": mitre_mapping,
                "confidence_result": confidence_result,
                "decision_result": decision_result,
                "task_result": task_result,
            }
        )

    return results

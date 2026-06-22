"""Report Generator for creating comprehensive target reports."""
from datetime import datetime
from typing import Any, Dict, Iterable

from sqlalchemy import or_, select
from sqlalchemy.orm import load_only

from app.database import async_session
from app.models import (
    AutoLoopDecision,
    DecisionScore,
    EvidenceConfidence,
    LearningFeedback,
    NormalizedResult,
    OpenPort,
    PortCveMatch,
    Target,
    ToolResult,
    ToolTask,
)

__all__ = ["generate_target_report"]


def _risk_score(value: float | None) -> float:
    return float(value or 0)


def _severity_rank(severity: str | None) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return ranks.get((severity or "").lower(), 0)


def _decision_created_at(decision: DecisionScore) -> Any:
    return decision.created_at or datetime.min


def _is_final_stop_decision(decision: DecisionScore | None) -> bool:
    return bool(
        decision
        and decision.next_action == "stop"
        and decision.next_tool is None
    )


def _parsed_value(parsed_output: Any, *keys: str) -> Any:
    if not isinstance(parsed_output, dict):
        return None

    for key in keys:
        value = parsed_output.get(key)
        if value is not None:
            return value
    return None


def _is_http_service(port: OpenPort) -> bool:
    service = (port.service or "").lower()
    return service in {"http", "https"} or port.port in {80, 443, 8000, 8080, 8443}


def _service_label(port: OpenPort) -> str:
    service = port.service or "unknown"
    product = f" {port.product}" if port.product else ""
    version = f" {port.version}" if port.version else ""
    return f"{service}{product}{version}".strip()


def _remediation_for_port(port: OpenPort) -> Dict[str, Any]:
    service = (port.service or "").lower()
    if "ssh" in service:
        guidance = "Disable password login, restrict access by firewall/VPN, and enforce key-based authentication."
    elif _is_http_service(port):
        guidance = "Patch the framework/server, enforce TLS, and run safe vulnerability validation."
    elif any(db in service for db in ("mysql", "postgresql", "microsoft sql")):
        guidance = "Restrict exposure, enforce strong authentication, and disable public bind where possible."
    else:
        guidance = "Identify the service owner, validate business need, and restrict unnecessary exposure."

    return {
        "port": port.port,
        "protocol": port.protocol,
        "service": port.service,
        "severity": None,
        "recommendation": guidance,
        "guidance": guidance,
    }


def _remediation_for_decision(decision: DecisionScore, port: OpenPort | None) -> Dict[str, Any]:
    service = port.service if port else None
    port_number = port.port if port else None
    protocol = port.protocol if port else None
    severity = (decision.severity or "").lower()
    next_action = (decision.next_action or "").lower()
    guidance = (
        f"Prioritize remediation for {service or 'affected service'} based on "
        f"{decision.severity or 'unknown'} risk decision."
    )
    if service:
        guidance = _remediation_for_port(port)["guidance"]
    if severity in {"critical", "high"}:
        guidance = (
            f"{guidance} Prioritize patching, restrict exposure, and confirm whether KEV/CVE matches apply."
        )
    elif severity == "medium":
        guidance = f"{guidance} Validate versions, harden configuration, and schedule patching."
    else:
        guidance = f"{guidance} Record the finding, monitor for change, and reduce unnecessary service exposure."

    return {
        "open_port_id": decision.open_port_id,
        "port": port_number,
        "protocol": protocol,
        "service": service,
        "severity": decision.severity,
        "risk_score": decision.risk_score,
        "recommendation": guidance,
        "guidance": guidance,
        "reason": decision.reason,
        "requires_remediation": next_action == "remediate",
        "requires_followup": next_action == "continue",
        "no_further_action": next_action == "stop",
    }


def _summarize_learning(feedback_rows: Iterable[LearningFeedback]) -> Dict[str, Any]:
    rows = list(feedback_rows)
    successful = [row for row in rows if row.success is True]
    failed = [row for row in rows if row.success is False]
    scores = [row.learning_score for row in rows if row.learning_score is not None]
    by_tool: Dict[str, Dict[str, Any]] = {}

    for feedback in rows:
        tool_name = feedback.tool_name or "unknown"
        bucket = by_tool.setdefault(
            tool_name,
            {
                "tool_name": tool_name,
                "total": 0,
                "successful": 0,
                "failed": 0,
                "average_learning_score": None,
                "services": [],
                "recommended_actions": [],
            },
        )
        bucket["total"] += 1
        if feedback.success is True:
            bucket["successful"] += 1
        elif feedback.success is False:
            bucket["failed"] += 1
        if feedback.service and feedback.service not in bucket["services"]:
            bucket["services"].append(feedback.service)
        if feedback.recommended_action and feedback.recommended_action not in bucket["recommended_actions"]:
            bucket["recommended_actions"].append(feedback.recommended_action)

    for tool_name, bucket in by_tool.items():
        tool_scores = [
            row.learning_score
            for row in rows
            if (row.tool_name or "unknown") == tool_name and row.learning_score is not None
        ]
        if tool_scores:
            bucket["average_learning_score"] = sum(tool_scores) / len(tool_scores)

    return {
        "total_feedback": len(rows),
        "successful": len(successful),
        "failed": len(failed),
        "average_learning_score": sum(scores) / len(scores) if scores else None,
        "by_tool": list(by_tool.values()),
    }


def _learning_tool_score(feedback_rows: Iterable[LearningFeedback]) -> list[Dict[str, Any]]:
    rows = list(feedback_rows)
    by_tool: Dict[str, list[LearningFeedback]] = {}
    for row in rows:
        by_tool.setdefault(row.tool_name or "unknown", []).append(row)

    scores = []
    for tool_name, tool_rows in sorted(by_tool.items()):
        learning_scores = [row.learning_score for row in tool_rows if row.learning_score is not None]
        avg_learning_score = sum(learning_scores) / len(learning_scores) if learning_scores else None
        scores.append(
            {
                "tool_name": tool_name,
                "feedback_count": len(tool_rows),
                "success_count": len([row for row in tool_rows if row.success is True]),
                "avg_learning_score": avg_learning_score,
                "final_learning_score": avg_learning_score if avg_learning_score is not None else 0.5,
            }
        )
    return scores


async def generate_target_report(target_id: int) -> Dict[str, Any]:
    """Generate a structured report for a target showing scan results, decisions, and remediation guidance."""
    async with async_session() as session:
        target = await session.get(Target, target_id)
        if not target:
            return {"error": "Target not found", "status": 404}

        ports = (
            await session.execute(
                select(OpenPort)
                .where(OpenPort.target_id == target_id)
                .order_by(OpenPort.port)
            )
        ).scalars().all()

        tool_results = (
            await session.execute(
                select(ToolResult)
                .options(
                    load_only(
                        ToolResult.id,
                        ToolResult.target_id,
                        ToolResult.scan_run_id,
                        ToolResult.open_port_id,
                        ToolResult.tool_task_id,
                        ToolResult.tool_name,
                        ToolResult.command,
                        ToolResult.parsed_output,
                        ToolResult.success,
                        ToolResult.risk_level,
                        ToolResult.evidence,
                        ToolResult.created_at,
                    )
                )
                .where(ToolResult.target_id == target_id)
                .order_by(ToolResult.created_at)
            )
        ).scalars().all()

        tool_tasks = (
            await session.execute(
                select(ToolTask)
                .where(ToolTask.target_id == target_id)
                .order_by(ToolTask.created_at)
            )
        ).scalars().all()

        decision_scores = (
            await session.execute(
                select(DecisionScore)
                .where(DecisionScore.target_id == target_id)
                .order_by(DecisionScore.risk_score.desc(), DecisionScore.created_at.desc())
            )
        ).scalars().all()

        evidence_confidence = (
            await session.execute(
                select(EvidenceConfidence)
                .where(EvidenceConfidence.target_id == target_id)
                .order_by(EvidenceConfidence.created_at)
            )
        ).scalars().all()

        normalized_results = (
            await session.execute(
                select(NormalizedResult)
                .where(NormalizedResult.target_id == target_id)
                .order_by(NormalizedResult.created_at)
            )
        ).scalars().all()

        auto_loop_decisions = (
            await session.execute(
                select(AutoLoopDecision)
                .where(AutoLoopDecision.target_id == target_id)
                .order_by(AutoLoopDecision.round_number)
            )
        ).scalars().all()

        learning_feedback = (
            await session.execute(
                select(LearningFeedback)
                .where(
                    or_(
                        LearningFeedback.decision_id.in_(
                            select(DecisionScore.id).where(DecisionScore.target_id == target_id)
                        ),
                        LearningFeedback.tool_result_id.in_(
                            select(ToolResult.id).where(ToolResult.target_id == target_id)
                        ),
                    )
                )
                .order_by(LearningFeedback.created_at.desc())
            )
        ).scalars().all()

        cve_matches = (
            await session.execute(
                select(PortCveMatch)
                .where(PortCveMatch.target_id == target_id)
                .order_by(PortCveMatch.open_port_id, PortCveMatch.id.desc())
            )
        ).scalars().all()

        port_by_id = {port.id: port for port in ports}
        cves_by_port: dict[int, list[dict[str, Any]]] = {}
        matched_cves = []
        for match in cve_matches:
            item = {
                "cve_id": match.cve_id,
                "open_port_id": match.open_port_id,
                "product": match.product,
                "version": match.version,
                "cvss": match.cvss,
                "epss": match.epss,
                "kev": match.kev,
                "match_type": match.match_type,
                "match_confidence": match.match_confidence,
                "source": match.source,
            }
            matched_cves.append(item)
            cves_by_port.setdefault(match.open_port_id, []).append(item)
        decisions_by_risk = sorted(
            decision_scores,
            key=lambda decision: (_risk_score(decision.risk_score), _severity_rank(decision.severity)),
            reverse=True,
        )
        latest_decision = max(
            decision_scores,
            key=lambda decision: (_decision_created_at(decision), decision.id or 0),
            default=None,
        )
        highest_risk_decision = decisions_by_risk[0] if decisions_by_risk else None
        high_risk_decisions = [
            decision
            for decision in decisions_by_risk
            if (decision.severity or "").lower() in {"critical", "high"} or _risk_score(decision.risk_score) >= 7
        ]

        high_risk_ports = []
        seen_high_risk_ports = set()
        for decision in high_risk_decisions:
            port = port_by_id.get(decision.open_port_id)
            if port and port.id not in seen_high_risk_ports:
                seen_high_risk_ports.add(port.id)
                high_risk_ports.append(
                    {
                        "open_port_id": port.id,
                        "port": port.port,
                        "protocol": port.protocol,
                        "service": port.service,
                        "risk_score": decision.risk_score,
                        "severity": decision.severity,
                    }
                )

        high_risk_services = [
            {
                "service": _service_label(port),
                "port": port.port,
                "protocol": port.protocol,
                "reason": "internet-facing HTTP service" if _is_http_service(port) else "exposed sensitive service",
            }
            for port in ports
            if (port.service or "").lower() in {"ssh", "mysql", "postgresql", "microsoft sql"}
            or _is_http_service(port)
        ]
        recommended_decisions = [latest_decision] if _is_final_stop_decision(latest_decision) else decisions_by_risk
        recommended_next_actions = [
            {
                "next_action": decision.next_action,
                "next_tool": decision.next_tool,
                "risk_score": decision.risk_score,
                "severity": decision.severity,
                "reason": decision.reason,
            }
            for decision in recommended_decisions
            if decision is not None
            if decision.next_action or decision.next_tool
        ]

        target_summary = {
            "target_id": target.id,
            "target": target.target,
            "target_type": target.target_type,
            "scope": target.scope,
            "status": target.status,
            "current_round": target.current_round,
            "max_rounds": target.max_round,
            "open_port_count": len(ports),
            "tool_result_count": len(tool_results),
            "tool_task_count": len(tool_tasks),
            "decision_count": len(decision_scores),
            "decision_score_count": len(decision_scores),
            "learning_feedback_count": len(learning_feedback),
            "highest_risk_score": highest_risk_decision.risk_score if highest_risk_decision else None,
            "highest_severity": highest_risk_decision.severity if highest_risk_decision else None,
        }

        open_ports = [
            {
                "open_port_id": port.id,
                "scan_run_id": port.scan_run_id,
                "ip": port.ip,
                "port": port.port,
                "protocol": port.protocol,
                "service": port.service,
                "product": port.product,
                "version": port.version,
                "extra_info": port.extra_info,
                "state": port.state,
                "created_at": port.created_at,
                "matched_cves": cves_by_port.get(port.id, []),
            }
            for port in ports
        ]

        tool_results_data = []
        for result in tool_results:
            port = port_by_id.get(result.open_port_id)
            parsed_output = result.parsed_output or {}
            tool_results_data.append(
                {
                    "tool_result_id": result.id,
                    "scan_run_id": result.scan_run_id,
                    "open_port_id": result.open_port_id,
                    "tool_task_id": result.tool_task_id,
                    "tool_name": result.tool_name,
                    "success": result.success,
                    "command": result.command,
                    "risk_level": result.risk_level,
                    "evidence_type": _parsed_value(parsed_output, "evidence_type"),
                    "service": _parsed_value(parsed_output, "service") or (port.service if port else None),
                    "evidence": result.evidence,
                    "parsed_output": parsed_output,
                    "created_at": result.created_at,
                }
            )

        tool_tasks_data = [
            {
                "tool_task_id": task.id,
                "tool_name": task.tool_name,
                "status": task.status,
                "priority": task.priority,
                "open_port_id": task.open_port_id,
                "tool_run": task.tool_run,
                "decision_score_id": task.decision_score_id,
                "approval_status": task.approval_status,
                "approval_required": task.approval_required,
                "approval_reason": task.approval_reason,
                "reject_reason": task.reject_reason,
                "created_at": task.created_at,
            }
            for task in tool_tasks
        ]

        decision_scores_data = [
            {
                "decision_score_id": decision.id,
                "open_port_id": decision.open_port_id,
                "risk_score": decision.risk_score,
                "base_risk_score": decision.base_risk_score,
                "adjusted_risk_score": decision.adjusted_risk_score,
                "confidence_score": decision.confidence_score,
                "learning_adjustment": decision.learning_adjustment,
                "runtime_adjustment": decision.runtime_adjustment,
                "evidence_adjustment": decision.evidence_adjustment,
                "severity": decision.severity,
                "next_action": decision.next_action,
                "next_tool": decision.next_tool,
                "mitre_phase": decision.mitre_phase,
                "mitre_technique": decision.mitre_technique,
                "confidence": decision.confidence,
                "reason": decision.reason,
                "reasoning": decision.reasoning,
                "input_snapshot": decision.input_snapshot,
                "waf_detected": decision.waf_detected,
                "tool_blocked": decision.tool_blocked,
                "tool_timeout": decision.tool_timeout,
                "created_at": decision.created_at,
            }
            for decision in decisions_by_risk
        ]

        mitre_mapping = []
        seen_mitre = set()
        for decision in decisions_by_risk:
            if not (decision.mitre_phase or decision.mitre_technique):
                continue
            mitre_key = (decision.mitre_phase, decision.mitre_technique)
            if mitre_key in seen_mitre:
                continue
            seen_mitre.add(mitre_key)
            mitre_mapping.append(
                {
                    "decision_score_id": decision.id,
                    "mitre_phase": decision.mitre_phase,
                    "mitre_technique": decision.mitre_technique,
                    "risk_score": decision.risk_score,
                    "severity": decision.severity,
                    "next_tool": decision.next_tool,
                    "reason": decision.reason,
                }
            )

        remediation = [
            _remediation_for_decision(decision, port_by_id.get(decision.open_port_id))
            for decision in decisions_by_risk
            if _severity_rank(decision.severity) >= _severity_rank("medium")
        ]
        if not remediation:
            remediation = [_remediation_for_port(port) for port in ports]
        evidence_confidence_data = [
            {
                "evidence_confidence_id": evidence.id,
                "open_port_id": evidence.open_port_id,
                "decision_score_id": evidence.decision_score_id,
                "tool_result_id": evidence.tool_result_id,
                "tool_name": evidence.tool_name,
                "evidence_type": evidence.evidence_type,
                "confidence_score": evidence.confidence_score,
                "confidence_reason": evidence.confidence_reason,
                "supporting_evidence": evidence.supporting_evidence,
                "contradictory_evidence": evidence.contradictory_evidence,
                "created_at": evidence.created_at,
            }
            for evidence in evidence_confidence
        ]
        normalized_results_data = [
            {
                "normalized_result_id": normalized.id,
                "open_port_id": normalized.open_port_id,
                "tool_result_id": normalized.tool_result_id,
                "tool_name": normalized.tool_name,
                "evidence_type": normalized.evidence_type,
                "normalized_output": normalized.normalized_output,
                "created_at": normalized.created_at,
            }
            for normalized in normalized_results
        ]
        auto_loop_decisions_data = [
            {
                "auto_loop_decision_id": auto_decision.id,
                "round": auto_decision.round_number,
                "next_tool": auto_decision.next_tool,
                "reason": auto_decision.stop_reason,
                "created_at": auto_decision.created_at,
            }
            for auto_decision in auto_loop_decisions
        ]
        learning_feedback_data = [
            {
                "learning_feedback_id": feedback.id,
                "decision_id": feedback.decision_id,
                "tool_result_id": feedback.tool_result_id,
                "tool_name": feedback.tool_name,
                "success": feedback.success,
                "service": feedback.service,
                "evidence_type": feedback.evidence_type,
                "recommended_action": feedback.recommended_action,
                "confidence_delta": getattr(feedback, "confidence_delta", None),
                "learning_score": feedback.learning_score,
                "reason": feedback.reason,
                "feedback": feedback.feedback,
                "created_at": feedback.created_at,
            }
            for feedback in learning_feedback
        ]

        risk_ranking = {
            "highest_risk_score": highest_risk_decision.risk_score if highest_risk_decision else None,
            "highest_severity": highest_risk_decision.severity if highest_risk_decision else None,
            "high_risk_ports": high_risk_ports,
            "high_risk_services": high_risk_services,
            "highest_risk_decision": decision_scores_data[0] if decision_scores_data else None,
            "recommended_next_actions": recommended_next_actions,
            "decisions_by_risk": decision_scores_data,
        }
        learning_feedback_summary = _summarize_learning(learning_feedback)
        learning_tool_score = _learning_tool_score(learning_feedback)

        return {
            "target_summary": target_summary,
            "target": target_summary,
            "open_ports": open_ports,
            "tool_results": tool_results_data,
            "tool_tasks": tool_tasks_data,
            "normalized_results": normalized_results_data,
            "decision_scores": decision_scores_data,
            "mitre_mapping": mitre_mapping,
            "risk_ranking": risk_ranking,
            "remediation": remediation,
            "remediation_guidance": [item["guidance"] for item in remediation],
            "evidence_confidence": evidence_confidence_data,
            "auto_loop_decisions": auto_loop_decisions_data,
            "learning_feedback": learning_feedback_data,
            "learning_feedback_summary": learning_feedback_summary,
            "learning_tool_score": learning_tool_score,
            "matched_cves": matched_cves,
        }

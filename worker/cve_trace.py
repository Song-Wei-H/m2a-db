"""Build flat CVE validation trace rows for offline export and experiments."""

from __future__ import annotations

from typing import Any, Iterable


TRACE_VERSION = "cve-validation-trace-v1"


def build_cve_validation_trace(
    candidates: Iterable[dict[str, Any]],
    *,
    target_id: int,
    decisions: Iterable[dict[str, Any]] = (),
    tool_tasks: Iterable[dict[str, Any]] = (),
    tool_results: Iterable[dict[str, Any]] = (),
    evidence_rows: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    decisions_by_port = {row.get("open_port_id"): row for row in decisions}
    tasks_by_port = {row.get("open_port_id"): row for row in tool_tasks}
    results_by_task = {row.get("tool_task_id"): row for row in tool_results}
    evidence_by_port = {row.get("open_port_id"): row for row in evidence_rows}
    trace = []
    for candidate in candidates:
        port_id = candidate.get("open_port_id")
        decision = decisions_by_port.get(port_id, {})
        selected = bool(candidate.get("selected_for_validation"))
        task = tasks_by_port.get(port_id, {}) if selected else {}
        result = results_by_task.get(task.get("tool_task_id"), {})
        evidence = evidence_by_port.get(port_id, {})
        state = candidate.get("validation_status") or candidate.get("validation_state") or "VERSION_UNVERIFIED"
        trace.append(
            {
                "trace_version": TRACE_VERSION,
                "target_id": target_id,
                "scan_run_id": candidate.get("scan_run_id") or result.get("scan_run_id"),
                "decision_id": decision.get("decision_score_id"),
                "tool_task_id": task.get("tool_task_id"),
                "tool_result_id": result.get("tool_result_id"),
                "cve_id": candidate.get("cve_id") or candidate.get("cve"),
                "product": candidate.get("product"),
                "product_identity_confidence": candidate.get("product_identity_confidence"),
                "detected_version": candidate.get("version") or candidate.get("detected_version"),
                "version_status": candidate.get("version_status"),
                "match_type": candidate.get("match_type"),
                "applicability_confidence": candidate.get("applicability_confidence"),
                "cvss": candidate.get("cvss_score") if candidate.get("cvss_score") is not None else candidate.get("cvss"),
                "epss": candidate.get("epss"),
                "kev": bool(candidate.get("kev")),
                "validation_priority_score": candidate.get("validation_priority_score"),
                "validation_rank": candidate.get("validation_rank"),
                "selected_for_validation": selected,
                "tool_name": task.get("tool_name"),
                "decision": candidate.get("validation_decision") or candidate.get("decision"),
                "validation_attempted": bool(task),
                "validation_success": result.get("success") if result else None,
                "final_validation_state": state,
                "final_cve_state": state,
                "evidence_confidence": evidence.get("confidence_score"),
            }
        )
    return trace

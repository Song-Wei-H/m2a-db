"""Thin Decision Engine.

Risk Engine v2 owns scoring.
Decision Engine only converts decision_scores into task intent.

This file also keeps decide_next_action() for backward compatibility
with analysis_pipeline.py during the migration.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "decide_next_action",
    "decide_next_action_from_risk_score",
]


def decide_next_action_from_risk_score(decision_score: Any) -> dict[str, Any]:
    severity = getattr(decision_score, "severity", None)
    risk_score = float(getattr(decision_score, "risk_score", 0) or 0)
    next_action = getattr(decision_score, "next_action", None)
    next_tool = getattr(decision_score, "next_tool", None)

    if not next_action:
        if severity == "critical":
            next_action = "remediate"
        elif severity == "high":
            next_action = "verify"
        elif severity == "medium":
            next_action = "continue"
        else:
            next_action = "stop"

    requires_approval = next_action in {
        "verify",
        "remediate",
        "manual_review",
    }

    if severity == "critical":
        priority = 100
    elif severity == "high":
        priority = 80
    elif severity == "medium":
        priority = 50
    else:
        priority = 10

    return {
        "recommended_tool": next_tool,
        "recommended_action": next_action,
        "priority": priority,
        "requires_approval": requires_approval,
        "risk_score": risk_score,
        "severity": severity,
        "reasoning": [
            "Decision derived from Risk Engine v2",
            f"risk_score={risk_score}",
            f"severity={severity}",
            f"next_action={next_action}",
            f"next_tool={next_tool}",
        ],
    }


def decide_next_action(
    evidence: dict[str, Any],
    mitre_mapping: dict[str, Any],
    confidence_result: dict[str, Any],
) -> dict[str, Any]:
    """Backward-compatible wrapper for old analysis_pipeline.py callers."""

    evidence_type = evidence.get("evidence_type")
    details = evidence.get("details") or {}

    service = str(
        evidence.get("service")
        or details.get("service")
        or ""
    ).lower()

    confidence = float(
        confidence_result.get("confidence_score")
        or confidence_result.get("confidence")
        or 0.5
    )

    if evidence_type == "vulnerability":
        recommended_tool = "nuclei_safe"
        recommended_action = "verify"
        priority = 80
        requires_approval = True

    elif evidence_type == "http_service":
        recommended_tool = "dirb_safe"
        recommended_action = "enumerate"
        priority = 50
        requires_approval = False

    elif evidence_type == "network_service":
        if service in {"http", "https", "http-proxy"}:
            recommended_tool = "httpx_basic"
            recommended_action = "discover"
        elif service == "ssh":
            recommended_tool = "ssh-enum"
            recommended_action = "enumerate"
        elif service in {"mysql", "mariadb"}:
            recommended_tool = "mysql-info"
            recommended_action = "enumerate"
        else:
            recommended_tool = None
            recommended_action = "no_action"

        priority = 50
        requires_approval = False

    else:
        recommended_tool = None
        recommended_action = "no_action"
        priority = 0
        requires_approval = False

    return {
        "recommended_tool": recommended_tool,
        "recommended_action": recommended_action,
        "priority": priority,
        "requires_approval": requires_approval,
        "risk_score": confidence,
        "risk_factors": {
            "compatibility_mode": True,
            "confidence": confidence,
        },
        "reasoning": [
            "Backward-compatible decision generated",
            f"evidence_type={evidence_type}",
            f"service={service}",
            f"confidence={confidence}",
            f"recommended_tool={recommended_tool}",
            f"recommended_action={recommended_action}",
        ],
    }
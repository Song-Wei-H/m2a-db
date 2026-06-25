"""Rule-free feature vector construction for future training."""

from __future__ import annotations

from typing import Any


FEATURE_VECTOR_VERSION = "round-feature-v1"


FEATURE_COLUMNS = [
    "open_port_count",
    "vuln_count",
    "avg_cvss",
    "has_kev",
    "service_count",
    "evidence_count",
    "current_round",
    "max_round",
    "learning_score",
    "waf_detected",
    "candidate_count",
    "selected_tool",
    "offline_prior",
    "ucb_score",
    "hybrid_score",
]


def build_round_features(
    *,
    target_state: dict[str, Any],
    decision_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    decision_snapshot = decision_snapshot or {}
    rank_scores = decision_snapshot.get("tool_rank_scores") or []
    selected_tool = decision_snapshot.get("selected_tool") or decision_snapshot.get("next_tool")
    selected_rank = _selected_rank(rank_scores, selected_tool)

    return {
        "open_port_count": int(target_state.get("open_port_count") or 0),
        "vuln_count": int(target_state.get("vuln_count") or target_state.get("vulnerability_count") or 0),
        "avg_cvss": _float_default(target_state.get("avg_cvss")),
        "has_kev": bool(target_state.get("has_kev")),
        "service_count": int(target_state.get("service_count") or 0),
        "evidence_count": int(target_state.get("evidence_count") or 0),
        "current_round": int(target_state.get("current_round") or 0),
        "max_round": int(target_state.get("max_round") or target_state.get("max_rounds") or 0),
        "learning_score": _float_default(target_state.get("learning_score"), default=0.5),
        "waf_detected": bool(target_state.get("waf_detected")),
        "candidate_count": len(decision_snapshot.get("candidate_tools") or []),
        "selected_tool": selected_tool,
        "offline_prior": _float_default(selected_rank.get("offline_prior_score"), default=0.5),
        "ucb_score": _float_default(selected_rank.get("ucb_score"), default=0.0),
        "hybrid_score": _float_default(selected_rank.get("hybrid_score"), default=0.0),
        "feature_vector_version": FEATURE_VECTOR_VERSION,
    }


def _selected_rank(rank_scores: list[dict[str, Any]], selected_tool: str | None) -> dict[str, Any]:
    if selected_tool:
        for rank in rank_scores:
            if rank.get("tool_name") == selected_tool:
                return rank
    return rank_scores[0] if rank_scores else {}


def _float_default(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

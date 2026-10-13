"""Deterministic CVE candidate selection for reports and bounded LLM context."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from worker.cve_validation_policy import select_validation_candidates


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _rank(item: dict[str, Any]) -> tuple[float, float, float, float, str]:
    confidence = _number(item.get("match_confidence"))
    cvss = _number(item.get("cvss_score") if item.get("cvss_score") is not None else item.get("cvss"))
    epss = _number(item.get("epss"))
    score = (
        (1000 if item.get("kev") else 0)
        + (500 if item.get("match_type") == "exact_cpe_version" else 0)
        + confidence * 100
        + cvss * 10
        + epss * 100
    )
    return (
        _number(item.get("validation_priority_score")),
        score,
        cvss,
        epss,
        f"{str(item.get('cve_id') or item.get('cve') or '')}:"
        f"{str(item.get('open_port_id') if item.get('open_port_id') is not None else 'target')}",
    )


def _mandatory(item: dict[str, Any]) -> bool:
    confidence = _number(item.get("match_confidence"))
    cvss = _number(item.get("cvss_score") if item.get("cvss_score") is not None else item.get("cvss"))
    epss = _number(item.get("epss"))
    return bool(
        item.get("kev")
        or item.get("match_type") == "exact_cpe_version"
        or (confidence >= 0.7 and cvss >= 9.0)
        or (confidence >= 0.7 and epss >= 0.1)
    )


def prioritize_cve_candidates(candidates: Iterable[dict[str, Any]], display_budget: int = 50) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Keep all mandatory candidates and fill remaining display budget by risk."""
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in candidates:
        cve_id = str(item.get("cve_id") or item.get("cve") or "").upper()
        if not cve_id:
            continue
        context = str(item.get("open_port_id") if item.get("open_port_id") is not None else "target")
        key = (cve_id, context)
        current = deduped.get(key)
        if current is None or _rank(item) > _rank(current):
            deduped[key] = item

    _, evaluated = select_validation_candidates(deduped.values())
    ordered = sorted(evaluated, key=_rank, reverse=True)
    mandatory = [item for item in ordered if _mandatory(item)]
    optional = [item for item in ordered if not _mandatory(item)]
    # Report rendering is a strict presentation budget. Mandatory status still
    # affects ranking/summary, but cannot expand an unbounded product list.
    selected = ordered[: max(display_budget, 0)]
    selected_ids = {
        (str(item.get("cve_id") or item.get("cve")).upper(),
         str(item.get("open_port_id") if item.get("open_port_id") is not None else "target"))
        for item in selected
    }
    match_types = Counter(str(item.get("match_type") or "unknown") for item in ordered)
    summary = {
        "total_candidates": len(ordered),
        "selected_candidates": len(selected),
        "mandatory_candidates": len(mandatory),
        "summarized_candidates": len(ordered) - len(selected),
        "kev_candidates": sum(bool(item.get("kev")) for item in ordered),
        "critical_candidates": sum(str(item.get("severity") or "").lower() == "critical" for item in ordered),
        "exact_version_candidates": match_types.get("exact_cpe_version", 0),
        "product_only_candidates": match_types.get("cpe_product_only", 0),
        "selected_cve_ids": sorted({item[0] for item in selected_ids}),
        "selected_candidate_contexts": len(selected_ids),
        "validation_selected_candidates": sum(bool(item.get("selected_for_validation")) for item in ordered),
        "selection_policy": "strict Top-N by validation priority; mandatory attributes influence rank but never bypass the display budget",
    }
    return selected, summary

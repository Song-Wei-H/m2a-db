"""Deterministic confidence-driven CVE validation policy.

Product identity estimates whether the observed target is the candidate product.
Version status is filtering evidence, never a validation prerequisite.
Priority determines which eligible candidate should be validated first.
Threat intelligence never changes a candidate into a validated finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


POLICY_VERSION = "confidence-driven-cve-v2"
MAX_CVE_VALIDATIONS_PER_ROUND = 3
MIN_PRODUCT_IDENTITY_CONFIDENCE = 0.70

APPLICABILITY_BASELINES = {
    "service_only": 0.15,
    "product_only": 0.30,
    "cpe_product_only": 0.55,
    "product_version": 0.75,
    "exact_cpe_version": 0.95,
    "cpe_version": 0.95,
    "validated_evidence": 1.0,
    "version_not_applicable": 0.0,
}

PRODUCT_IDENTITY_BASELINES = {
    "service_only": 0.10,
    "technology_only": 0.45,
    "product_only": 0.75,
    "cpe_product_only": 0.92,
    "product_version": 0.85,
    "exact_cpe_version": 0.98,
    "cpe_version": 0.98,
    "validated_evidence": 1.0,
    "version_not_applicable": 0.98,
}


def _clamp(value: float) -> float:
    return max(0.0, min(float(value), 1.0))


def _number(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def applicability_confidence(candidate: dict[str, Any]) -> float:
    """Score target applicability without CVSS, EPSS, or KEV inputs."""
    match_type = str(candidate.get("match_type") or "service_only")
    baseline = APPLICABILITY_BASELINES.get(match_type, 0.10)
    source_confidence = _clamp(_number(candidate.get("match_confidence")))
    evidence_confidence = candidate.get("evidence_confidence")
    if evidence_confidence is None:
        evidence_confidence = source_confidence
    evidence_confidence = _clamp(_number(evidence_confidence))
    # The match class remains authoritative; supporting evidence can move the
    # estimate by at most 0.10 and cannot turn a product-only hit into proof.
    evidence_adjustment = (evidence_confidence - 0.5) * 0.20
    return round(_clamp(baseline + evidence_adjustment), 4)


def product_identity_confidence(candidate: dict[str, Any]) -> float:
    """Estimate product identity independently from detected version."""
    explicit = candidate.get("product_identity_confidence")
    if explicit is not None:
        return round(_clamp(_number(explicit)), 4)
    match_type = str(candidate.get("match_type") or "service_only")
    return PRODUCT_IDENTITY_BASELINES.get(match_type, 0.10)


def version_status(candidate: dict[str, Any]) -> str:
    explicit = str(candidate.get("version_status") or "").upper()
    if explicit in {"KNOWN", "UNKNOWN", "INFERRED", "CONFLICTING"}:
        return explicit
    detected = candidate.get("detected_version", candidate.get("version"))
    return "KNOWN" if detected not in (None, "", "*") else "UNKNOWN"


def validation_priority_score(candidate: dict[str, Any], product_identity: float) -> float:
    """Rank validation value; this score is not target vulnerability risk."""
    cvss = _clamp(_number(candidate.get("cvss_score", candidate.get("cvss"))) / 10.0)
    epss = _clamp(_number(candidate.get("epss")))
    kev = 1.0 if candidate.get("kev") else 0.0
    evidence = _clamp(_number(candidate.get("evidence_confidence", candidate.get("match_confidence"))))
    score = product_identity * 0.45 + cvss * 0.20 + epss * 0.15 + kev * 0.15 + evidence * 0.05
    return round(_clamp(score), 4)


def initial_validation_state(candidate: dict[str, Any]) -> str:
    match_type = str(candidate.get("match_type") or "")
    if match_type == "version_not_applicable":
        return "NOT_APPLICABLE"
    if match_type == "validated_evidence":
        return "VALIDATED"
    if match_type in {"exact_cpe_version", "cpe_version", "product_version"}:
        return "VERSION_APPLICABLE"
    return "VERSION_UNRESOLVED"


def evaluate_candidate(candidate: dict[str, Any], *, compatible_tool: bool = True) -> dict[str, Any]:
    result = dict(candidate)
    applicability = applicability_confidence(result)
    identity = product_identity_confidence(result)
    detected_version_status = version_status(result)
    applicability_state = initial_validation_state(result)
    priority = validation_priority_score(result, identity)
    product_relevant = bool(result.get("product")) and identity >= MIN_PRODUCT_IDENTITY_CONFIDENCE
    state = applicability_state
    if state == "NOT_APPLICABLE" or not product_relevant:
        decision = "SKIP"
    elif not compatible_tool:
        decision = "DEFER"
        state = "DEFERRED"
    else:
        decision = "VERIFY"
        state = "VALIDATION_PENDING"
    result.update(
        product_identity_confidence=identity,
        version_status=detected_version_status,
        applicability_state=applicability_state,
        applicability_confidence=applicability,
        validation_priority_score=priority,
        validation_state=state,
        decision=decision,
        policy_version=POLICY_VERSION,
    )
    return result


def select_validation_candidates(
    candidates: Iterable[dict[str, Any]],
    *,
    compatible_tool: bool = True,
    limit: int = MAX_CVE_VALIDATIONS_PER_ROUND,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evaluated = [evaluate_candidate(item, compatible_tool=compatible_tool) for item in candidates]
    evaluated.sort(
        key=lambda item: (
            item["validation_priority_score"],
            item["product_identity_confidence"],
            str(item.get("cve_id") or item.get("cve") or ""),
        ),
        reverse=True,
    )
    selected = [item for item in evaluated if item["decision"] == "VERIFY"][: max(0, limit)]
    selected_ids = {str(item.get("cve_id") or item.get("cve")) for item in selected}
    for rank, item in enumerate(evaluated, start=1):
        item["validation_rank"] = rank
        item_id = str(item.get("cve_id") or item.get("cve"))
        item["selected_for_validation"] = item_id in selected_ids
        if item["decision"] == "VERIFY" and item_id not in selected_ids:
            item["decision"] = "DEFER"
            item["validation_state"] = "DEFERRED"
            item["defer_reason"] = "TOP_N_LIMIT"
    return selected, evaluated

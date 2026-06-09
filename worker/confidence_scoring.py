"""Confidence scoring module.

This module provides deterministic, rule-based scoring of evidence objects in
conjunction with their MITRE ATT&CK mapping. It performs no external calls,
subprocesses, or database writes.
"""

from __future__ import annotations

from typing import Any

__all__ = ["calculate_confidence"]


BASE_SCORE_MAP = {
    "critical": 9,
    "high": 7,
    "medium": 5,
    "low": 3,
    "info": 1,
}


_CONFIDENCE_THRESHOLD_MAP = [
    (0.95, "critical"),
    (0.90, "high"),
    (0.75, "medium"),
    (0.50, "low"),
]


_EVIDENCE_CONTRIB = {
    "vulnerability": 3,
    "http_service": 2,
    "content_discovery": 1,
    "ssh_service": 2,
    "database_service": 2,
}


_MITRE_CONTRIB = {
    "T1190": 2,
    "T1021": 2,
    "T1213": 2,
    "T1083": 1,
}


_FINAL_SEVERITY_MAP = [
    (9, "critical"),
    (7, "high"),
    (5, "medium"),
    (3, "low"),
]


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _base_score_from_confidence(confidence: float) -> int:
    """Return the base score for a numeric confidence value."""
    for threshold, severity in _CONFIDENCE_THRESHOLD_MAP:
        if confidence >= threshold:
            return BASE_SCORE_MAP[severity]
    return BASE_SCORE_MAP["info"]


def _severity_from_score(score: float) -> str:
    """Return severity string based on final score thresholds."""
    for threshold, severity in _FINAL_SEVERITY_MAP:
        if score >= threshold:
            return severity
    return "info"


def calculate_confidence(
    evidence: dict[str, Any],
    mitre_mapping: dict[str, Any],
) -> dict[str, Any]:
    """Calculate a deterministic confidence score for an evidence item."""
    reasoning: list[str] = []

    evidence_confidence = _safe_float(evidence.get("confidence", 0.0))
    base_score = _base_score_from_confidence(evidence_confidence)
    reasoning.append(
        f"Base score from evidence confidence {evidence_confidence:.2f} => {base_score}"
    )

    evidence_type = str(evidence.get("evidence_type", ""))
    evidence_contribution = _EVIDENCE_CONTRIB.get(evidence_type, 0)
    reasoning.append(
        f"Evidence type '{evidence_type}' contribution => +{evidence_contribution}"
    )

    technique_id = mitre_mapping.get("technique_id")
    technique_id_text = str(technique_id) if technique_id is not None else ""
    mitre_contribution = _MITRE_CONTRIB.get(technique_id_text, 0)
    reasoning.append(
        f"MITRE technique '{technique_id_text}' contribution => +{mitre_contribution}"
    )

    total_score = base_score + evidence_contribution + mitre_contribution
    severity = _severity_from_score(total_score)

    reasoning.append(f"Total score => {total_score}")
    reasoning.append(f"Derived severity => '{severity}' based on score {total_score}")

    return {
        "confidence_score": float(total_score),
        "severity": severity,
        "reasoning": reasoning,
    }
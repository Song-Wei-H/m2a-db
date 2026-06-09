"""MITRE ATT&CK mapping module.

This module provides deterministic mapping from normalized evidence objects to
ATT&CK tactic/technique information. No external calls, subprocesses, or
LLM logic are used.
"""

from __future__ import annotations

from typing import Any

__all__ = ["map_to_mitre"]


# Mapping definitions
_HTTP_TACTIC = "Initial Access"
_HTTP_TECH_ID = "T1190"
_HTTP_TECH_NAME = "Exploit Public-Facing Application"

_CONTENT_TACTIC = "Discovery"
_CONTENT_TECH_ID = "T1083"
_CONTENT_TECH_NAME = "File and Directory Discovery"

_SSH_TACTIC = "Lateral Movement"
_SSH_TECH_ID = "T1021"
_SSH_TECH_NAME = "Remote Services"

_DB_TACTIC = "Collection"
_DB_TECH_ID = "T1213"
_DB_TECH_NAME = "Data from Information Repositories"


def _evidence_ref(evidence: dict[str, Any]) -> str:
    """Return the deterministic evidence reference."""
    ref = evidence.get("evidence_ref")
    return str(ref) if ref is not None else ""


def _empty_mapping(evidence: dict[str, Any]) -> dict[str, Any]:
    """Return a stable empty mapping for evidence with no deterministic ATT&CK mapping."""
    return {
        "tactic": None,
        "technique_id": None,
        "technique_name": None,
        "confidence": 0.0,
        "evidence_ref": _evidence_ref(evidence),
    }


def _mapping(
    *,
    tactic: str,
    technique_id: str,
    technique_name: str,
    confidence: float,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Build a stable ATT&CK mapping object."""
    return {
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "confidence": confidence,
        "evidence_ref": _evidence_ref(evidence),
    }


def map_to_mitre(evidence: dict[str, Any]) -> dict[str, Any]:
    """Map a normalized evidence object to deterministic ATT&CK information."""
    evidence_type = evidence.get("evidence_type")

    if evidence_type == "http_service":
        return _mapping(
            tactic=_HTTP_TACTIC,
            technique_id=_HTTP_TECH_ID,
            technique_name=_HTTP_TECH_NAME,
            confidence=0.95,
            evidence=evidence,
        )

    if evidence_type == "content_discovery":
        return _mapping(
            tactic=_CONTENT_TACTIC,
            technique_id=_CONTENT_TECH_ID,
            technique_name=_CONTENT_TECH_NAME,
            confidence=0.90,
            evidence=evidence,
        )

    if evidence_type == "ssh_service":
        return _mapping(
            tactic=_SSH_TACTIC,
            technique_id=_SSH_TECH_ID,
            technique_name=_SSH_TECH_NAME,
            confidence=0.90,
            evidence=evidence,
        )

    if evidence_type == "database_service":
        return _mapping(
            tactic=_DB_TACTIC,
            technique_id=_DB_TECH_ID,
            technique_name=_DB_TECH_NAME,
            confidence=0.90,
            evidence=evidence,
        )

    if evidence_type == "vulnerability":
        return _mapping(
            tactic=_HTTP_TACTIC,
            technique_id=_HTTP_TECH_ID,
            technique_name=_HTTP_TECH_NAME,
            confidence=0.95,
            evidence=evidence,
        )

    return _empty_mapping(evidence)
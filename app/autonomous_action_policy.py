"""Fail-closed, versioned autonomous policy candidate for home synthetic actions."""
from __future__ import annotations

import json
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

from app.action_contracts import ACTION_IDENTITIES, ACTION_REQUIRED_ATTACK_DEPTH, TOOL_BY_ACTION
from app.target_identity import TargetIdentityError, VerifiedTargetIdentity, validate_target_identity_proof

POLICY_PATH = Path(__file__).resolve().parents[1] / "home-lab" / "action-contracts" / "autonomous-policy-v1.json"
ADVANCED_CONTRACT_PATH = Path(__file__).resolve().parents[1] / "home-lab" / "action-contracts" / "advanced-synthetic-v1.json"
POLICY_ID = "gade-home-autonomous-policy-v1"


def configured_target_identity() -> str | None:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = policy.get("required_target_identity")
    return value if isinstance(value, str) and value else None


def _evidence_types(target, tool_name: str, evidence_refs: list[dict] | None) -> set[str]:
    found: set[str] = set()
    for ref in evidence_refs or []:
        if not isinstance(ref, dict) or not isinstance(ref.get("content"), dict):
            continue
        kind = ref.get("type")
        content = ref["content"]
        try:
            canonical = json.dumps(content, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            digest = hashlib.sha256(canonical.encode()).hexdigest()
        except (TypeError, ValueError):
            continue
        if (not ref.get("reference") or ref.get("sha256") != digest
                or ref.get("evidence_id") != f"sha256:{digest}"):
            continue
        if kind == "registered_target":
            if (ref.get("reference") == f"targets:{target.id}"
                    and content == {"target": target.target, "scope": target.scope}):
                found.add(kind)
        elif kind == "decision_input":
            if content.get("next_tool") == tool_name and content.get("next_action"):
                found.add(kind)
    return found


def evaluate_autonomous_action(*, action_id: str, tool_name: str, target, parameters: dict,
                               evidence_refs: list[dict] | None, ttl_seconds: int,
                               home_lab_enabled: bool,
                               target_identity_proof: VerifiedTargetIdentity | None = None,
                               allow_mock_identity: bool = False) -> dict:
    """Return deterministic ALLOW/DENY; never grants authority itself."""
    try:
        policy_bytes = POLICY_PATH.read_bytes()
        contract_bytes = ADVANCED_CONTRACT_PATH.read_bytes()
        l4_contract_bytes = (POLICY_PATH.parent / "l4-synthetic-role-lease-v1.json").read_bytes()
        policy = json.loads(policy_bytes)
        contract = json.loads(contract_bytes)
    except (OSError, ValueError):
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_POLICY_UNAVAILABLE"}
    entry = policy.get("actions", {}).get(action_id)
    if not isinstance(entry, dict) or entry.get("decision") != "ALLOW":
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_ACTION_NOT_ALLOWLISTED"}
    if (policy.get("policy_id") != POLICY_ID
            or policy.get("environment") != "HOME_LAB_EXPLORATORY"
            or policy.get("status") != "CANDIDATE_DISABLED_BY_DEFAULT"
            or policy.get("target_identity_proof_max_age_seconds") != 60
            or policy.get("target_identity_runtime_recheck") != "required-before-worker-action"
            or policy.get("target_identity_binding") != (
                "integrity-hashed AuthorizationDecision snapshot bound to grant id + fresh independent verifier proof; endpoint/scope are additional constraints only")
            or os.getenv("GADE_HOME_AUTONOMOUS_POLICY_VERSION") != policy.get("policy_id")
            or not home_lab_enabled):
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_POLICY_NOT_ENABLED"}
    if policy.get("required_target_identity") != contract.get("target_identity"):
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_TARGET_IDENTITY_MISMATCH"}
    if (hashlib.sha256(contract_bytes).hexdigest() != policy.get("source_contract_sha256")
            or hashlib.sha256(l4_contract_bytes).hexdigest() != policy.get("l4_contract_sha256")):
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_SOURCE_CONTRACT_CHANGED"}
    contract_action = next((item for item in contract.get("actions", [])
                            if item.get("action_id") == action_id), None)
    if (contract_action is None or entry.get("tool") != contract_action.get("tool")
            or entry.get("depth") != contract_action.get("depth")
            or entry.get("path") != contract_action.get("path")
            or entry.get("effect") != contract_action.get("effect")
            or contract.get("target") != "127.0.0.1:18080"
            or contract.get("scope") != policy.get("required_scope")
            or entry.get("approval_mode") != "autonomous_policy_supersedes_individual_approval_for_this_action_only"):
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_POLICY_CONTRACT_MISMATCH"}
    now = datetime.now(UTC).replace(tzinfo=None)
    expiry = getattr(target, "authorization_expires_at", None)
    effective = getattr(target, "authorization_effective_from", None)
    if (getattr(target, "authorization_policy_version", None) != policy.get("profile_policy_version")
            or getattr(target, "authorization_configured_by", None) != "operator-ui"
            or effective is None or effective > now or expiry is None or expiry <= now):
        return {"outcome": "DENY", "reason_code": "TARGET_POLICY_PROFILE_INVALID"}
    depth = entry.get("depth")
    if ((getattr(target, "authorization_depth", 1) or 1) < depth
            or ACTION_REQUIRED_ATTACK_DEPTH.get(action_id) != depth
            or TOOL_BY_ACTION.get(action_id) != tool_name):
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_DEPTH_OR_ACTION_MISMATCH"}
    if (target.target != policy.get("required_target")
            or target.scope != policy.get("required_scope")
            or target.target_type != "ip"
            or parameters.get("target") != target.target
            or parameters.get("host") != target.target
            or parameters.get("port") != 18080
            or ACTION_IDENTITIES.get(action_id) != entry.get("execution_identity")):
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_SCOPE_OR_IDENTITY_MISMATCH"}
    if (not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0
            or ttl_seconds > min(60, policy.get("maximum_grant_ttl_seconds", 0))):
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_TTL_INVALID"}
    present = _evidence_types(target, tool_name, evidence_refs)
    missing = sorted(set(entry.get("required_evidence_types", [])) - present)
    if missing:
        return {"outcome": "DENY", "reason_code": "AUTONOMOUS_EVIDENCE_REQUIRED", "missing": missing}
    try:
        proof = validate_target_identity_proof(
            target_identity_proof, target=target, expected_identity=policy["required_target_identity"],
            port=18080, allow_mock=allow_mock_identity,
        )
    except TargetIdentityError as exc:
        return {"outcome": "DENY", "reason_code": exc.reason_code}
    return {"outcome": "ALLOW", "reason_code": "AUTONOMOUS_POLICY_MATCH",
            "policy_id": policy["policy_id"], "action_id": action_id, "validation_tier": depth,
            "target_identity_check": "PASS", "target_identity": proof.target_identity,
            "target_identity_verifier": proof.verifier_id,
            "target_identity_fingerprint": proof.identity_fingerprint,
            "target_identity_expires_at": proof.expires_at.isoformat()}

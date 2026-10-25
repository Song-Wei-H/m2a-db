"""Fail-closed integration seam for authoritative one-use dispatch permits.

This module deliberately does not implement an authority or cryptographic
protocol. Deployments must inject an authenticated verifier backed by durable,
shared revocation state. Tests may inject a deterministic fake verifier.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from uuid import UUID

from app.config import settings


MAX_PERMIT_TTL = timedelta(seconds=30)
PERMIT_BINDING_VERSION = "gade-dispatch-permit-binding-v1"


class DispatchPermitError(RuntimeError):
    def __init__(self, state: str, reason_code: str):
        super().__init__(reason_code)
        if state not in {"DENIED", "UNKNOWN"}:
            raise ValueError("dispatch permit error state must be DENIED or UNKNOWN")
        self.state = state
        self.reason_code = reason_code


class DispatchPermitVerifier(Protocol):
    """Trusted adapter contract, not implemented by the current repository.

    ``issue_permit`` must resolve the supplied IDs against authoritative live
    Grant/Target/Approval records rather than trust the caller's snapshot.
    ``consume_permit`` must authenticate the Worker and atomically compare the
    stored binding/current revocation epochs while consuming the one-use Permit.
    Its ALLOW/IN_FLIGHT result is the serialization point: later revocation
    cannot retroactively cancel an admitted effect. Implementations must retain
    durable state for replay handling; a process-local lock is not sufficient.
    """
    async def issue_permit(self, binding: dict[str, Any]) -> dict[str, Any]: ...

    def consume_permit(self, permit_id: str, binding: dict[str, Any]) -> dict[str, Any]: ...


_configured_verifier: DispatchPermitVerifier | None = None


def configure_dispatch_permit_verifier(verifier: DispatchPermitVerifier | None) -> None:
    """Register a trusted process-local adapter during service startup.

    No adapter is registered by this repository's current app startup paths;
    callers therefore fail closed when an Action opts in.
    """
    global _configured_verifier
    _configured_verifier = verifier


def get_dispatch_permit_verifier() -> DispatchPermitVerifier | None:
    return _configured_verifier


def permit_utcnow() -> datetime:
    return datetime.now(timezone.utc)


def required_dispatch_permit_actions() -> frozenset[str]:
    """Read only server-side configuration and reject unknown Action IDs."""
    raw = settings.dispatch_permit_required_actions_list
    if not raw:
        return frozenset()
    from app.action_contracts import ACTION_BY_TOOL, HOME_ADVANCED_ACTIONS

    known = set(ACTION_BY_TOOL.values())
    known.update(action for action, _depth, _path in HOME_ADVANCED_ACTIONS.values())
    requested = frozenset(raw)
    unknown = requested - known
    if unknown:
        raise DispatchPermitError("UNKNOWN", "DISPATCH_PERMIT_ACTION_CONFIGURATION_INVALID")
    return requested


def dispatch_permit_required(action_id: str | None) -> bool:
    return action_id is not None and action_id in required_dispatch_permit_actions()


def canonical_binding_sha256(binding: dict[str, Any]) -> str:
    payload = json.dumps(binding, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_utc(value: Any, reason_code: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise DispatchPermitError("UNKNOWN", reason_code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DispatchPermitError("UNKNOWN", reason_code) from exc
    if parsed.tzinfo is None:
        raise DispatchPermitError("UNKNOWN", reason_code)
    return parsed.astimezone(timezone.utc)


def normalize_authority_decision(result: Any) -> tuple[str, str, str | None]:
    """Return (state, reason, admission_id), never treating malformed as ALLOW."""
    if not isinstance(result, dict):
        return "UNKNOWN", "DISPATCH_VERIFIER_RESPONSE_INVALID", None
    decision = result.get("decision")
    if decision == "DENY":
        return "DENIED", str(result.get("reason_code") or "DISPATCH_PERMIT_DENIED"), None
    if decision != "ALLOW" or result.get("state") != "IN_FLIGHT":
        return "UNKNOWN", str(result.get("reason_code") or "DISPATCH_VERIFIER_OUTCOME_UNKNOWN"), None
    admission_id = result.get("admission_id")
    try:
        UUID(str(admission_id))
    except (ValueError, TypeError, AttributeError):
        return "UNKNOWN", "DISPATCH_ADMISSION_ID_INVALID", None
    return "IN_FLIGHT", "DISPATCH_ADMITTED", str(admission_id)


def validate_permit_envelope(
    envelope: Any,
    request: Any,
    *,
    now: datetime | None = None,
) -> tuple[str, dict[str, Any], str]:
    """Validate shape, freshness and request binding before authority consume."""
    if not isinstance(envelope, dict):
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_REQUIRED")
    permit_id = envelope.get("permit_id")
    try:
        UUID(str(permit_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_ID_INVALID") from exc
    binding = envelope.get("binding")
    if not isinstance(binding, dict):
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_BINDING_MISSING")
    if envelope.get("binding_sha256") != canonical_binding_sha256(binding):
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_BINDING_HASH_MISMATCH")
    if binding.get("schema_version") != PERMIT_BINDING_VERSION:
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_BINDING_VERSION_MISMATCH")

    expected = {
        "task_id": getattr(request, "task_id", None),
        "authorization_id": getattr(request, "authorization_id", None),
        "target_id": getattr(request, "target_id", None),
        "action_id": getattr(request, "action_id", None),
        "target": getattr(request, "target", None),
        "parameters_hash": getattr(request, "authorization_parameters_hash", None),
        "execution_identity": getattr(request, "execution_identity", None),
        "depth": getattr(request, "validation_tier", None),
        "template_id": getattr(request, "template_id", None),
        "request_id": getattr(request, "request_id", None),
        "correlation_id": getattr(request, "correlation_id", None),
        "worker_build_sha256": getattr(request, "expected_worker_build_sha256", None),
    }
    if any(value is None for value in expected.values()):
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_REQUEST_BINDING_INCOMPLETE")
    if any(binding.get(key) != value for key, value in expected.items()):
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_REQUEST_BINDING_MISMATCH")

    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    permit_expiry = parse_utc(envelope.get("expires_at"), "DISPATCH_PERMIT_EXPIRY_INVALID")
    grant_expiry = parse_utc(binding.get("grant_expires_at"), "DISPATCH_GRANT_EXPIRY_INVALID")
    if permit_expiry <= now_utc or grant_expiry <= now_utc:
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_OR_GRANT_EXPIRED")
    if permit_expiry > min(grant_expiry, now_utc + MAX_PERMIT_TTL):
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_TTL_INVALID")

    for key in ("target_scope_epoch", "grant_scope_epoch"):
        if not isinstance(binding.get(key), int) or isinstance(binding.get(key), bool):
            raise DispatchPermitError("UNKNOWN", "AUTHORITATIVE_SCOPE_EPOCH_MISSING")
    if binding.get("target_scope") != binding.get("grant_scope"):
        raise DispatchPermitError("DENIED", "DISPATCH_PERMIT_SCOPE_MISMATCH")
    if not isinstance(binding.get("approval_required"), bool):
        raise DispatchPermitError("UNKNOWN", "APPROVAL_STATE_UNAVAILABLE")
    if binding.get("approval_required"):
        for key in ("approval_epoch", "grant_approval_epoch"):
            if not isinstance(binding.get(key), int) or isinstance(binding.get(key), bool):
                raise DispatchPermitError("UNKNOWN", "AUTHORITATIVE_APPROVAL_EPOCH_MISSING")
        if binding.get("approval_status") != "approved":
            raise DispatchPermitError("DENIED", "APPROVAL_NOT_CURRENTLY_APPROVED")
    return str(permit_id), binding, envelope["binding_sha256"]


@dataclass(frozen=True)
class PermitIssue:
    permit_id: str
    expires_at: str
    binding_sha256: str


def validate_permit_issue(
    result: Any,
    binding: dict[str, Any],
    *,
    now: datetime | None = None,
) -> PermitIssue:
    if not isinstance(result, dict):
        raise DispatchPermitError("UNKNOWN", "DISPATCH_PERMIT_ISSUE_RESPONSE_INVALID")
    if result.get("decision") == "DENY":
        raise DispatchPermitError("DENIED", str(result.get("reason_code") or "DISPATCH_PERMIT_ISSUE_DENIED"))
    if result.get("decision") != "ALLOW":
        raise DispatchPermitError("UNKNOWN", str(result.get("reason_code") or "DISPATCH_PERMIT_ISSUE_UNKNOWN"))
    permit_id = result.get("permit_id")
    try:
        UUID(str(permit_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DispatchPermitError("UNKNOWN", "DISPATCH_PERMIT_ID_INVALID") from exc
    expires_at = result.get("expires_at")
    permit_expiry = parse_utc(expires_at, "DISPATCH_PERMIT_EXPIRY_INVALID")
    grant_expiry = parse_utc(binding.get("grant_expires_at"), "DISPATCH_GRANT_EXPIRY_INVALID")
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if permit_expiry <= now_utc or permit_expiry > min(grant_expiry, now_utc + MAX_PERMIT_TTL):
        raise DispatchPermitError("UNKNOWN", "DISPATCH_PERMIT_TTL_INVALID")
    expected_hash = canonical_binding_sha256(binding)
    if result.get("binding_sha256") != expected_hash:
        raise DispatchPermitError("UNKNOWN", "DISPATCH_PERMIT_BINDING_HASH_MISMATCH")
    return PermitIssue(str(permit_id), str(expires_at), expected_hash)

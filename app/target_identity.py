"""Fail-closed target identity verification primitives.

No production verifier is configured in this repository. A live verifier must
derive its proof from an authenticated target-side challenge (for example a
signature under an operator-pinned key), never from a Proposal or endpoint
string. Tests may inject an explicitly marked MOCK verifier to exercise the
control flow; mock proofs are not live identity evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol


MAX_IDENTITY_PROOF_AGE_SECONDS = 60
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class TargetIdentityError(ValueError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class VerifiedTargetIdentity:
    """Verifier output; fields must be derived outside the AI proposal path."""

    target_id: int
    target_identity: str
    endpoint: str
    port: int
    scope: str
    verifier_id: str
    identity_fingerprint: str
    evidence_sha256: str
    verified_at: datetime
    expires_at: datetime
    verification_mode: str  # LIVE_VERIFIED or MOCK


class TargetIdentityVerifier(Protocol):
    def verify_target(self, *, target: Any, expected_identity: str, port: int) -> VerifiedTargetIdentity:
        """Independently authenticate the responder for this registered target."""


def get_configured_target_identity_verifier() -> TargetIdentityVerifier | None:
    """No real target-side attestation source is configured yet."""
    return None


def _now_utc(now: datetime | None = None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None:
        raise TargetIdentityError("TARGET_IDENTITY_UNVERIFIED", "identity clock must be timezone-aware")
    return value.astimezone(UTC)


def canonical_sha256(value: dict[str, Any]) -> str:
    material = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def verify_registered_target_identity(*, target: Any, expected_identity: str, port: int,
                                     verifier: TargetIdentityVerifier | None,
                                     now: datetime | None = None,
                                     allow_mock: bool = False) -> VerifiedTargetIdentity:
    """Ask a separately configured verifier; never accept identity from AI data."""
    if verifier is None:
        raise TargetIdentityError("TARGET_IDENTITY_UNVERIFIED", "no trusted target identity verifier is configured")
    try:
        proof = verifier.verify_target(target=target, expected_identity=expected_identity, port=port)
    except Exception as exc:
        raise TargetIdentityError("TARGET_IDENTITY_VERIFIER_UNAVAILABLE", "trusted target verifier failed") from exc
    return validate_target_identity_proof(proof, target=target, expected_identity=expected_identity,
                                          port=port, now=now, allow_mock=allow_mock)


def validate_target_identity_proof(proof: Any, *, target: Any, expected_identity: str, port: int,
                                   now: datetime | None = None,
                                   allow_mock: bool = False) -> VerifiedTargetIdentity:
    """Validate verifier output before it can influence authorization."""
    if not isinstance(proof, VerifiedTargetIdentity):
        raise TargetIdentityError("TARGET_IDENTITY_UNVERIFIED", "verifier returned no typed identity proof")
    current = _now_utc(now)
    try:
        issued = _now_utc(proof.verified_at)
        expiry = _now_utc(proof.expires_at)
    except (TypeError, AttributeError) as exc:
        raise TargetIdentityError("TARGET_IDENTITY_UNVERIFIED", "identity proof timestamps are invalid") from exc
    if proof.verification_mode == "MOCK" and not allow_mock:
        raise TargetIdentityError("TARGET_IDENTITY_UNVERIFIED", "mock identity proof cannot authorize runtime execution")
    if proof.verification_mode not in {"LIVE_VERIFIED", "MOCK"}:
        raise TargetIdentityError("TARGET_IDENTITY_UNVERIFIED", "unknown identity verification mode")
    if (proof.target_id != getattr(target, "id", None)
            or proof.target_identity != expected_identity
            or proof.endpoint != getattr(target, "target", None)
            or proof.port != port
            or proof.scope != getattr(target, "scope", None)
            or not isinstance(proof.verifier_id, str) or not proof.verifier_id.strip()
            or not _SHA256_RE.fullmatch(str(proof.identity_fingerprint))
            or not _SHA256_RE.fullmatch(str(proof.evidence_sha256))):
        raise TargetIdentityError("TARGET_IDENTITY_MISMATCH", "verified identity does not match the registered target contract")
    if (issued > current or expiry <= current
            or expiry - issued > timedelta(seconds=MAX_IDENTITY_PROOF_AGE_SECONDS)
            or current - issued > timedelta(seconds=MAX_IDENTITY_PROOF_AGE_SECONDS)):
        raise TargetIdentityError("TARGET_IDENTITY_EVIDENCE_EXPIRED", "target identity evidence is stale or expired")
    return proof


def build_grant_identity_binding(*, proof: VerifiedTargetIdentity, target: Any, grant: Any) -> dict[str, Any]:
    """Bind verified identity evidence to the existing grant's immutable fields."""
    binding = {
        "schema_version": 1,
        "target_id": int(target.id),
        "target_identity": proof.target_identity,
        "endpoint": proof.endpoint,
        "port": proof.port,
        "scope": proof.scope,
        "verifier_id": proof.verifier_id,
        "identity_fingerprint": proof.identity_fingerprint,
        "evidence_sha256": proof.evidence_sha256,
        "verification_mode": proof.verification_mode,
        "verified_at": _iso(proof.verified_at),
        "identity_expires_at": _iso(proof.expires_at),
        "authorization_id": int(grant.id),
        "proposal_id": int(grant.proposal_id),
        "action_id": grant.action_id,
        "execution_identity": grant.execution_identity,
        "parameters_hash": grant.parameters_hash,
        "grant_expires_at": _iso(grant.expires_at.replace(tzinfo=UTC)
                                  if grant.expires_at.tzinfo is None else grant.expires_at),
    }
    binding["binding_sha256"] = canonical_sha256(binding)
    return binding


def validate_binding_record(binding: Any, *, now: datetime | None = None,
                            allow_mock: bool = False) -> str | None:
    """Validate the persisted binding snapshot without contacting the target."""
    if not isinstance(binding, dict):
        return "TARGET_IDENTITY_BINDING_MISSING"
    material = {key: value for key, value in binding.items() if key != "binding_sha256"}
    if (binding.get("schema_version") != 1
            or not _SHA256_RE.fullmatch(str(binding.get("binding_sha256", "")))
            or canonical_sha256(material) != binding.get("binding_sha256")):
        return "TARGET_IDENTITY_BINDING_INTEGRITY_FAILED"
    if binding.get("verification_mode") == "MOCK" and not allow_mock:
        return "TARGET_IDENTITY_UNVERIFIED"
    if binding.get("verification_mode") not in {"LIVE_VERIFIED", "MOCK"}:
        return "TARGET_IDENTITY_UNVERIFIED"
    for field in ("identity_fingerprint", "evidence_sha256"):
        if not _SHA256_RE.fullmatch(str(binding.get(field, ""))):
            return "TARGET_IDENTITY_BINDING_INTEGRITY_FAILED"
    try:
        current = _now_utc(now)
        verified = datetime.fromisoformat(str(binding["verified_at"]).replace("Z", "+00:00")).astimezone(UTC)
        identity_expiry = datetime.fromisoformat(str(binding["identity_expires_at"]).replace("Z", "+00:00")).astimezone(UTC)
        grant_expiry = datetime.fromisoformat(str(binding["grant_expires_at"]).replace("Z", "+00:00")).astimezone(UTC)
    except (KeyError, TypeError, ValueError, AttributeError):
        return "TARGET_IDENTITY_UNVERIFIED"
    if (verified > current or current - verified > timedelta(seconds=MAX_IDENTITY_PROOF_AGE_SECONDS)
            or identity_expiry <= current or grant_expiry <= current):
        return "TARGET_IDENTITY_EVIDENCE_EXPIRED"
    return None


def target_identity_binding_for_grant(decision: Any, grant: Any) -> dict[str, Any] | None:
    """Read the identity binding only from the integrity-checked decision for this grant."""
    snapshot = getattr(decision, "contract_snapshot", None)
    if (not isinstance(snapshot, dict) or getattr(decision, "outcome", None) != "ALLOW"
            or getattr(decision, "authorization_id", None) != getattr(grant, "id", None)
            or getattr(decision, "proposal_id", None) != getattr(grant, "proposal_id", None)):
        return None
    expected = {
        key: (getattr(grant, key).isoformat() if isinstance(getattr(grant, key, None), datetime)
              else getattr(grant, key, None))
        for key in ("id", "proposal_id", "target_id", "investigation_id", "action_id",
                    "canonical_parameters", "parameters_hash", "execution_identity", "template_version",
                    "validation_tier", "scope", "execution_limit", "expires_at", "authorization_source")
    }
    for key, value in expected.items():
        if snapshot.get(key) != value:
            return None
    fields = ("proposal_id", "authorization_id", "outcome", "reason", "policy_source", "contract_snapshot")
    decision_input = {key: getattr(decision, key, None) for key in fields}
    if getattr(decision, "record_hash", None) != canonical_sha256(decision_input):
        return None
    binding = snapshot.get("target_identity_binding")
    try:
        verified_at = datetime.fromisoformat(str(binding["verified_at"]).replace("Z", "+00:00"))
    except (TypeError, ValueError, KeyError):
        return None
    if validate_binding_record(binding, now=verified_at, allow_mock=True) is not None:
        return None
    if (binding.get("authorization_id") != grant.id or binding.get("proposal_id") != grant.proposal_id
            or binding.get("target_id") != grant.target_id or binding.get("action_id") != grant.action_id
            or binding.get("execution_identity") != grant.execution_identity
            or binding.get("parameters_hash") != grant.parameters_hash):
        return None
    return dict(binding)


def verify_runtime_target_identity(*, binding: dict[str, Any] | None, target: Any,
                                   action_id: str, execution_identity: str,
                                   parameters_hash: str, authorization_id: int | None,
                                   verifier: TargetIdentityVerifier | None,
                                   now: datetime | None = None,
                                   allow_mock: bool = False) -> str | None:
    """Re-authenticate the responder immediately before a Worker Action."""
    reason = validate_binding_record(binding, now=now, allow_mock=allow_mock)
    if reason:
        return reason
    assert binding is not None
    if (authorization_id is None or binding.get("authorization_id") != authorization_id
            or binding.get("target_id") != getattr(target, "id", None)
            or binding.get("endpoint") != getattr(target, "target", None)
            or binding.get("target_identity") != "gade-l2-t1078"
            or binding.get("endpoint") != "127.0.0.1"
            or binding.get("port") != 18080
            or binding.get("scope") != "127.0.0.1/32"
            or binding.get("scope") != getattr(target, "scope", None)
            or binding.get("action_id") != action_id
            or binding.get("execution_identity") != execution_identity
            or binding.get("parameters_hash") != parameters_hash):
        return "TARGET_IDENTITY_BINDING_MISMATCH"
    try:
        proof = verify_registered_target_identity(
            target=target, expected_identity=str(binding.get("target_identity")), port=18080,
            verifier=verifier, now=now, allow_mock=allow_mock,
        )
    except TargetIdentityError as exc:
        return exc.reason_code
    if (proof.verifier_id != binding.get("verifier_id")
            or proof.identity_fingerprint != binding.get("identity_fingerprint")):
        return "TARGET_IDENTITY_CHANGED"
    return None

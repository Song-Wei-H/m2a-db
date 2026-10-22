from datetime import datetime
from typing import List

from sqlalchemy import Boolean, DateTime, Float, Integer, BigInteger, Numeric, SmallInteger, String, Text, func
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(50))
    scope: Mapped[str | None] = mapped_column(String(50))
    authorization_depth: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="1")
    authorization_policy_version: Mapped[str] = mapped_column(String(50), nullable=False, server_default="legacy-safe-default")
    authorization_effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, server_default=func.now())
    authorization_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))
    authorization_configured_by: Mapped[str] = mapped_column(String(100), nullable=False, server_default="legacy-record")
    status: Mapped[str] = mapped_column(String(50), server_default="pending")
    current_round: Mapped[int] = mapped_column(Integer, default=1)
    max_round: Mapped[int] = mapped_column(Integer, default=5)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )
    # Relationship to auto loop decisions
    auto_loop_decisions: Mapped[List["AutoLoopDecision"]] = relationship("AutoLoopDecision", back_populates="target")

class ToolRegistry(Base):
    __tablename__ = "tool_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool_name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    profile_id: Mapped[str | None] = mapped_column(String(50))
    template_id: Mapped[str | None] = mapped_column(String(50))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )

class ExecutionProfile(Base):
    __tablename__ = "execution_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    container_image: Mapped[str | None] = mapped_column(
        String(255)
    )
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, server_default="300")
    network_mode: Mapped[str] = mapped_column(String(50), nullable=False, server_default="bridge")
    readonly_fs: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())

class ToolRequest(Base):
    __tablename__ = "tool_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    requested_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    requested_capability: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    reasoning_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(50), server_default="pending_review")
    reviewer: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)



class CommandTemplate(Base):
    __tablename__ = "command_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    tool_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    argv_template: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
    )
    allowed_fields: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
    )
    risk_level: Mapped[str | None] = mapped_column(String(50))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )

class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(Integer)
    round: Mapped[int] = mapped_column(Integer, default=1)
    scan_type: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[str | None] = mapped_column(String(50))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )


class OpenPort(Base):
    __tablename__ = "open_ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(Integer)
    scan_run_id: Mapped[int | None] = mapped_column(Integer)
    ip: Mapped[str | None] = mapped_column(String(100))
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(20))
    service: Mapped[str | None] = mapped_column(String(100))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(255))
    extra_info: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(50), server_default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, nullable=False)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    raw_output: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )


class ToolResult(Base):
    __tablename__ = "tool_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(Integer)
    scan_run_id: Mapped[int | None] = mapped_column(Integer)
    open_port_id: Mapped[int | None] = mapped_column(Integer)
    tool_task_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("tool_tasks.id"))
    execution_receipt: Mapped[dict | None] = mapped_column(JSONB)
    output_hash: Mapped[str | None] = mapped_column(String(64))
    investigation_id: Mapped[str | None] = mapped_column(String(100))
    action_id: Mapped[str | None] = mapped_column(String(150))
    tool_name: Mapped[str | None] = mapped_column(String(100))
    command: Mapped[str | None] = mapped_column(Text)
    raw_output: Mapped[str | None] = mapped_column(Text)
    parsed_output: Mapped[dict | None] = mapped_column(JSONB)
    success: Mapped[bool] = mapped_column(Boolean, server_default="false")
    risk_level: Mapped[str | None] = mapped_column(String(50))
    evidence: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )


class NormalizedResult(Base):
    __tablename__ = "normalized_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(Integer)
    open_port_id: Mapped[int | None] = mapped_column(Integer)
    tool_result_id: Mapped[int | None] = mapped_column(Integer)
    tool_name: Mapped[str | None] = mapped_column(String(100))
    evidence_type: Mapped[str | None] = mapped_column(String(100))
    normalized_output: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )


class OsvPackageQueryCache(Base):
    """Latest bounded OSV query state for an exact package identity."""

    __tablename__ = "osv_package_query_cache"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cache_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(80), nullable=False)
    package_name: Mapped[str] = mapped_column(String(500), nullable=False)
    package_version: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, server_default="OSV")
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retry_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    response_sha256: Mapped[str | None] = mapped_column(String(64))
    last_attempt_sha256: Mapped[str | None] = mapped_column(String(64))
    response_summary: Mapped[dict | None] = mapped_column(JSONB)
    match_confidence: Mapped[float | None] = mapped_column(Float)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class OsvNormalizedEvidence(Base):
    """Links a persisted normalized result to an OSV query or explicit skip."""

    __tablename__ = "osv_normalized_evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    normalized_result_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("normalized_results.id", ondelete="CASCADE"), nullable=False
    )
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)
    cache_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("osv_package_query_cache.id", ondelete="SET NULL")
    )
    package_identity: Mapped[dict | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, server_default="OSV")
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    response_sha256: Mapped[str | None] = mapped_column(String(64))
    last_attempt_sha256: Mapped[str | None] = mapped_column(String(64))
    match_confidence: Mapped[float | None] = mapped_column(Float)
    evidence_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    result_summary: Mapped[dict | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ToolTask(Base):
    __tablename__ = "tool_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, server_default="pending")
    priority: Mapped[int] = mapped_column(Integer, default=5)
    reject_reason: Mapped[str | None] = mapped_column(Text)
    execution_request: Mapped[dict | None] = mapped_column(JSONB)
    execution_request_hash: Mapped[str | None] = mapped_column(String(64))
    execution_audit: Mapped[dict | None] = mapped_column(JSONB)

    approval_status: Mapped[str] = mapped_column(
        String(50), nullable=False, server_default="not_required"
    )
    approval_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    approval_reason: Mapped[str | None] = mapped_column(Text)
    proposal_reason: Mapped[str | None] = mapped_column(Text)
    approval_decision_reason: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))
    approved_by: Mapped[str | None] = mapped_column(String(255))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)
    open_port_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_run: Mapped[str | None] = mapped_column(String(100), nullable=True)
    decision_score_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    investigation_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    action_id: Mapped[str | None] = mapped_column(String(150), nullable=True)
    execution_authorization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("execution_authorizations.id"), nullable=True
    )

class AutoLoopDecision(Base):
    __tablename__ = "auto_loop_decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), nullable=False)
    round_number: Mapped[int] = mapped_column(Integer, nullable=False)
    stop_reason: Mapped[str] = mapped_column(String(50), nullable=True)
    next_tool: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())

    target: Mapped["Target"] = relationship("Target", back_populates="auto_loop_decisions")

class LearningFeedback(Base):
    __tablename__ = "learning_feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    decision_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("decision_scores.id", ondelete="SET NULL"),
        nullable=True,
    )
    tool_result_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    service: Mapped[str | None] = mapped_column(String(50), nullable=True)
    evidence_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(String(50), nullable=True)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    learning_score: Mapped[float] = mapped_column(Numeric(3, 1, asdecimal=False), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    feedback: Mapped[str |  None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(Integer)
    open_port_id: Mapped[int | None] = mapped_column(Integer)
    tool_result_id: Mapped[int | None] = mapped_column(Integer)
    cve: Mapped[str | None] = mapped_column(String(50))
    vuln_name: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(50))
    cvss: Mapped[float | None] = mapped_column(Float)
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, server_default="false")
    mitre_tactic: Mapped[str | None] = mapped_column(String(100))
    mitre_technique: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(50), server_default="unverified")
    evidence: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )


class CveEnrichment(Base):
    __tablename__ = "cve_enrichment"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(50))
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, server_default="false")
    affected_vendor: Mapped[str | None] = mapped_column(String(255))
    affected_product: Mapped[str | None] = mapped_column(String(255))
    affected_version: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str | None] = mapped_column(String(50))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))
    mitre_tactic: Mapped[str | None] = mapped_column(String(100))
    mitre_technique: Mapped[str | None] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )

class PortCveMatch(Base):
    __tablename__ = "port_cve_matches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)
    open_port_id: Mapped[int] = mapped_column(Integer, nullable=False)
    cve_id: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    cve: Mapped[str | None] = mapped_column(String(50))
    product: Mapped[str | None] = mapped_column(
        String(255)
    )
    version: Mapped[str | None] = mapped_column(
        String(255)
    )
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(50))
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(
        Boolean,
        server_default="false",
    )
    match_type: Mapped[str | None] = mapped_column(
        String(50)
    )
    match_confidence: Mapped[float | None] = mapped_column(
        Float
    )
    source: Mapped[str | None] = mapped_column(
        Text
    )
    match_reason: Mapped[str | None] = mapped_column(Text)
    affected_vendor: Mapped[str | None] = mapped_column(String(255))
    affected_product: Mapped[str | None] = mapped_column(String(255))
    affected_version: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )


class VulnerabilityCandidate(Base):
    """Assessment-scoped CVE/service/evidence lifecycle; never dedupe by CVE alone."""
    __tablename__ = "vulnerability_candidates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    cve: Mapped[str] = mapped_column(String(50), nullable=False)
    candidate_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    open_port_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("open_ports.id", ondelete="CASCADE"))
    service: Mapped[str | None] = mapped_column(String(100))
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    required_action: Mapped[str | None] = mapped_column(String(150))
    required_attack_depth: Mapped[int | None] = mapped_column(SmallInteger)
    priority: Mapped[float] = mapped_column(Float, nullable=False, server_default="0")
    status: Mapped[str] = mapped_column(String(40), nullable=False, server_default="DISCOVERED")
    validation_coverage: Mapped[str] = mapped_column(String(24), nullable=False, server_default="NOT_EVALUATED")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    authorization_decision_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("authorization_decisions.id"))
    execution_authorization_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("execution_authorizations.id"))
    tool_task_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("tool_tasks.id"))
    validation_result: Mapped[dict | None] = mapped_column(JSONB)
    terminal_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now(), onupdate=func.now())


class ValidationAction(Base):
    __tablename__ = "validation_actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_id: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    phase: Mapped[str] = mapped_column(String(50), nullable=False)
    validation_tier: Mapped[int] = mapped_column(Integer, nullable=False)
    execution_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    template_version: Mapped[str] = mapped_column(String(100), nullable=False)
    parameter_schema: Mapped[dict] = mapped_column(JSONB, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())


class DecisionProposal(Base):
    __tablename__ = "decision_proposals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(String(150), nullable=False)
    canonical_parameters: Mapped[dict] = mapped_column(JSONB, nullable=False)
    decision_score_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("decision_scores.id"))
    raw_proposal: Mapped[dict | None] = mapped_column(JSONB)
    evidence_refs: Mapped[list | None] = mapped_column(JSONB)
    input_hash: Mapped[str | None] = mapped_column(String(64))
    confidence: Mapped[float | None] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, server_default="proposed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())


class ExecutionAuthorization(Base):
    __tablename__ = "execution_authorizations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    proposal_id: Mapped[int] = mapped_column(Integer, ForeignKey("decision_proposals.id"), nullable=False)
    investigation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(String(150), nullable=False)
    canonical_parameters: Mapped[dict] = mapped_column(JSONB, nullable=False)
    parameters_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    template_version: Mapped[str] = mapped_column(String(100), nullable=False)
    validation_tier: Mapped[int] = mapped_column(Integer, nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    execution_limit: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    consumed_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    authorization_source: Mapped[str] = mapped_column(String(100), nullable=False)
    human_approved_by: Mapped[str | None] = mapped_column(String(255))
    human_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())


class AuthorizationDecision(Base):
    """An evaluation is not an executable grant. DENY/PENDING have no grant."""
    __tablename__ = "authorization_decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    proposal_id: Mapped[int] = mapped_column(Integer, ForeignKey("decision_proposals.id"), nullable=False)
    authorization_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("execution_authorizations.id"), unique=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    policy_source: Mapped[str] = mapped_column(String(100), nullable=False)
    contract_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())


class TargetCveMatch(Base):
    __tablename__ = "target_cve_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)
    cve_id: Mapped[str] = mapped_column(String(50), nullable=False)
    cve: Mapped[str | None] = mapped_column(String(50))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(255))
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(50))
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, server_default="false")
    match_type: Mapped[str | None] = mapped_column(String(50))
    match_confidence: Mapped[float | None] = mapped_column(Float)
    match_reason: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(Text)
    affected_vendor: Mapped[str | None] = mapped_column(String(255))
    affected_product: Mapped[str | None] = mapped_column(String(255))
    affected_version: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )

class EvidenceConfidence(Base):
    __tablename__ = "evidence_confidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(Integer)
    open_port_id: Mapped[int | None] = mapped_column(Integer)
    decision_score_id: Mapped[int | None] = mapped_column(Integer)
    tool_result_id: Mapped[int | None] = mapped_column(Integer)
    tool_name: Mapped[str | None] = mapped_column(String(100))
    evidence_type: Mapped[str | None] = mapped_column(String(100))
    confidence_score: Mapped[float | None] = mapped_column(Float)
    confidence_reason: Mapped[str | None] = mapped_column(Text)
    supporting_evidence: Mapped[dict | None] = mapped_column(JSONB)
    contradictory_evidence: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )


class DecisionScore(Base):
    __tablename__ = "decision_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)
    open_port_id: Mapped[int | None] = mapped_column(Integer)

    risk_score: Mapped[float] = mapped_column(Float, nullable=False)

    base_risk_score: Mapped[float | None] = mapped_column(Float)
    adjusted_risk_score: Mapped[float | None] = mapped_column(Float)
    confidence_score: Mapped[float | None] = mapped_column(Float)

    learning_adjustment: Mapped[float | None] = mapped_column(Float, default=0)
    runtime_adjustment: Mapped[float | None] = mapped_column(Float, default=0)
    evidence_adjustment: Mapped[float | None] = mapped_column(Float, default=0)

    waf_detected: Mapped[bool | None] = mapped_column(Boolean, default=False)
    tool_blocked: Mapped[bool | None] = mapped_column(Boolean, default=False)
    tool_timeout: Mapped[bool | None] = mapped_column(Boolean, default=False)

    severity: Mapped[str | None] = mapped_column(String(20))

    next_action: Mapped[str] = mapped_column(String(50), nullable=False)
    next_tool: Mapped[str | None] = mapped_column(String(100))

    mitre_phase: Mapped[str | None] = mapped_column(String(100))
    mitre_technique: Mapped[str | None] = mapped_column(String(100))

    confidence: Mapped[float | None] = mapped_column(Float)
    reason: Mapped[str | None] = mapped_column(Text)
    reasoning: Mapped[list | None] = mapped_column(JSONB)

    input_snapshot: Mapped[dict | None] = mapped_column(JSONB)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )

class LlmRecommendation(Base):
    __tablename__ = "llm_recommendations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(Integer)
    decision_score_id: Mapped[int | None] = mapped_column(Integer)
    evidence_confidence_id: Mapped[int | None] = mapped_column(Integer)
    recommended_action: Mapped[str | None] = mapped_column(
        String(50)
    )
    recommended_tool: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    confidence: Mapped[float | None] = mapped_column(Float)
    reasoning: Mapped[str | None] = mapped_column(Text)
    raw_response: Mapped[dict | None] = mapped_column(JSONB)
    approved: Mapped[bool] = mapped_column(
        Boolean,
        server_default="false",
    )
    validator_status: Mapped[str | None] = mapped_column(
        String(50)
    )
    validator_reason: Mapped[str | None] = mapped_column(
        Text
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )

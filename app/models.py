from datetime import datetime
from typing import List

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
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
    tool_task_id: Mapped[int | None] = mapped_column(Integer)
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

class ToolTask(Base):
    __tablename__ = "tool_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), server_default="pending")
    priority: Mapped[int] = mapped_column(Integer, default=5)
    reject_reason: Mapped[str | None] = mapped_column(Text)

    approval_status: Mapped[str] = mapped_column(
        String(50), nullable=False, server_default="not_required"
    )
    approval_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    approval_reason: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
    )
    target_id: Mapped[int] = mapped_column(Integer)
    open_port_id: Mapped[int] = mapped_column(Integer)
    tool_run: Mapped[str] = mapped_column(String(100))
    decision_score_id: Mapped[int] = mapped_column(Integer)

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
    learning_score: Mapped[float] = mapped_column(Float, nullable=False)
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
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, server_default="false")
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
    product: Mapped[str | None] = mapped_column(
        String(255)
    )
    version: Mapped[str | None] = mapped_column(
        String(255)
    )
    cvss: Mapped[float | None] = mapped_column(Float)
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

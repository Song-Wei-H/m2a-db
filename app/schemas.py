from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    target: str = Field(..., max_length=255, examples=["192.0.2.10"])
    target_type: Literal["ip", "domain", "cidr"] = "ip"
    scope: Literal["internal", "external"] = "internal"


class TargetCreateResponse(BaseModel):
    target_id: int
    scan_run_id: int
    status: str


class TargetRunStatusResponse(BaseModel):
    target_id: int
    target: str
    status: str
    current_round: int | None = None
    max_rounds: int | None = None
    pending_task_count: int = 0
    running_task_count: int = 0
    completed_task_count: int = 0
    failed_task_count: int = 0
    latest_decision: dict[str, Any] | None = None
    latest_next_action: str | None = None
    latest_next_tool: str | None = None
    report_ready: bool = False


class DecisionRunResponse(BaseModel):
    target_id: int
    next_action: str
    next_tool: str
    mitre_phase: str
    mitre_technique: str
    risk_score: float
    confidence: float
    reason: str


class OpenPortResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int | None
    scan_run_id: int | None
    ip: str | None
    port: int | None
    protocol: str | None
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    state: str | None
    created_at: datetime


class ReportTargetSummaryResponse(BaseModel):
    target_id: int | None = None
    target: str | None = None
    target_type: str | None = None
    scope: str | None = None
    status: str | None = None
    current_round: int | None = None
    max_rounds: int | None = None
    open_port_count: int = 0
    tool_result_count: int = 0
    decision_count: int = 0
    learning_feedback_count: int = 0
    highest_risk_score: float | None = None
    highest_severity: str | None = None


class ReportOpenPortResponse(BaseModel):
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    state: str | None = None


class ReportToolResultResponse(BaseModel):
    tool_name: str | None = None
    success: bool | None = None
    evidence_type: str | None = None
    service: str | None = None
    risk_level: str | None = None
    created_at: datetime | None = None
    parsed_output: dict[str, Any] | None = None


class ReportDecisionScoreResponse(BaseModel):
    risk_score: float | None = None
    severity: str | None = None
    next_action: str | None = None
    next_tool: str | None = None
    confidence: float | None = None
    reason: str | None = None
    mitre_phase: str | None = None
    mitre_technique: str | None = None


class ReportRecommendedActionResponse(BaseModel):
    next_action: str | None = None
    next_tool: str | None = None
    risk_score: float | None = None
    severity: str | None = None
    reason: str | None = None


class ReportRiskRankingResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    highest_risk_score: float | None = None
    highest_severity: str | None = None
    recommended_next_actions: list[ReportRecommendedActionResponse] = Field(default_factory=list)


class ReportMitreMappingResponse(BaseModel):
    mitre_phase: str | None = None
    mitre_technique: str | None = None


class ReportLearningFeedbackResponse(BaseModel):
    tool_name: str | None = None
    success: bool | None = None
    confidence_delta: float | None = None
    learning_score: float | None = None
    reason: str | None = None


class ReportRemediationResponse(BaseModel):
    severity: str | None = None
    recommendation: str | None = None


class TargetReportResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    target_summary: ReportTargetSummaryResponse
    open_ports: list[ReportOpenPortResponse] = Field(default_factory=list)
    tool_results: list[ReportToolResultResponse] = Field(default_factory=list)
    decision_scores: list[ReportDecisionScoreResponse] = Field(default_factory=list)
    risk_ranking: ReportRiskRankingResponse = Field(default_factory=ReportRiskRankingResponse)
    mitre_mapping: list[ReportMitreMappingResponse] = Field(default_factory=list)
    learning_feedback: list[ReportLearningFeedbackResponse] = Field(default_factory=list)
    remediation: list[ReportRemediationResponse] = Field(default_factory=list)
    matched_cves: list[dict[str, Any]] = Field(default_factory=list)

    target: dict[str, Any] | None = None
    tool_tasks: list[dict[str, Any]] = Field(default_factory=list)
    normalized_results: list[dict[str, Any]] = Field(default_factory=list)
    remediation_guidance: list[str] = Field(default_factory=list)
    evidence_confidence: list[dict[str, Any]] = Field(default_factory=list)
    auto_loop_decisions: list[dict[str, Any]] = Field(default_factory=list)
    learning_feedback_summary: dict[str, Any] = Field(default_factory=dict)


class TargetSummaryResponse(ReportTargetSummaryResponse):
    pass


class ToolResultResponse(ReportToolResultResponse):
    pass


class DecisionResponse(ReportDecisionScoreResponse):
    pass


class LearningFeedbackResponse(ReportLearningFeedbackResponse):
    pass


class DashboardOverviewResponse(BaseModel):
    targets_total: int = 0
    targets_completed: int = 0
    targets_running: int = 0
    targets_failed: int = 0
    tool_results_total: int = 0
    decisions_total: int = 0
    learning_feedback_total: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    cve_backed_findings: int = 0

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import DecisionScore, LearningFeedback, PortCveMatch, ScanRun, Target, ToolResult
from app.schemas import (
    DashboardOverviewResponse,
    DecisionResponse,
    LearningFeedbackResponse,
    TargetCreate,
    TargetCreateResponse,
    TargetReportResponse,
    TargetSummaryResponse,
    ToolResultResponse,
)
from worker.report_generator import generate_target_report

router = APIRouter(tags=["targets"])


async def _get_report_or_404(target_id: int):
    report = await generate_target_report(target_id)
    if "error" in report and report["error"] == "Target not found":
        raise HTTPException(status_code=404, detail="Target not found")
    return report


@router.get("/targets/{target_id}/report", response_model=TargetReportResponse)
async def get_target_report(target_id: int):
    """Generate and return a target report."""
    return await _get_report_or_404(target_id)


@router.get("/targets/{target_id}/summary", response_model=TargetSummaryResponse)
async def get_target_summary(target_id: int):
    """Return a lightweight target summary for dashboard views."""
    report = await _get_report_or_404(target_id)
    return report.get("target_summary", report.get("target", {}))


@router.get("/targets/{target_id}/tool-results", response_model=list[ToolResultResponse])
async def get_target_tool_results(target_id: int):
    """Return lightweight tool result data for dashboard views."""
    report = await _get_report_or_404(target_id)
    return sorted(
        report.get("tool_results", []),
        key=lambda result: result.get("created_at") or "",
        reverse=True,
    )


@router.get("/targets/{target_id}/decisions", response_model=list[DecisionResponse])
async def get_target_decisions(target_id: int):
    """Return target decisions ordered by highest risk first."""
    report = await _get_report_or_404(target_id)
    return report.get("decision_scores", [])


@router.get("/targets/{target_id}/learning-feedback", response_model=list[LearningFeedbackResponse])
async def get_target_learning_feedback(target_id: int):
    """Return target learning feedback ordered newest first."""
    report = await _get_report_or_404(target_id)
    return sorted(
        report.get("learning_feedback", []),
        key=lambda feedback: feedback.get("created_at") or "",
        reverse=True,
    )


@router.get("/dashboard/overview", response_model=DashboardOverviewResponse, tags=["dashboard"])
async def get_dashboard_overview(db: AsyncSession = Depends(get_db)) -> DashboardOverviewResponse:
    """Return aggregate dashboard counters without loading row payloads."""
    targets_total = await db.scalar(select(func.count(Target.id)))
    targets_completed = await db.scalar(select(func.count(Target.id)).where(Target.status == "completed"))
    targets_running = await db.scalar(select(func.count(Target.id)).where(Target.status == "running"))
    targets_failed = await db.scalar(select(func.count(Target.id)).where(Target.status == "failed"))
    tool_results_total = await db.scalar(select(func.count(ToolResult.id)))
    decisions_total = await db.scalar(select(func.count(DecisionScore.id)))
    learning_feedback_total = await db.scalar(select(func.count(LearningFeedback.id)))
    cve_backed_findings = await db.scalar(select(func.count(PortCveMatch.id)))
    critical_findings = await db.scalar(
        select(func.count(DecisionScore.id)).where(func.lower(DecisionScore.severity) == "critical")
    )
    high_findings = await db.scalar(
        select(func.count(DecisionScore.id)).where(func.lower(DecisionScore.severity) == "high")
    )
    medium_findings = await db.scalar(
        select(func.count(DecisionScore.id)).where(func.lower(DecisionScore.severity) == "medium")
    )

    return DashboardOverviewResponse(
        targets_total=targets_total or 0,
        targets_completed=targets_completed or 0,
        targets_running=targets_running or 0,
        targets_failed=targets_failed or 0,
        tool_results_total=tool_results_total or 0,
        decisions_total=decisions_total or 0,
        learning_feedback_total=learning_feedback_total or 0,
        critical_findings=critical_findings or 0,
        high_findings=high_findings or 0,
        medium_findings=medium_findings or 0,
        cve_backed_findings=cve_backed_findings or 0,
    )


@router.post(
    "/targets",
    response_model=TargetCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_target(
    body: TargetCreate,
    db: AsyncSession = Depends(get_db),
) -> TargetCreateResponse:
    target = Target(
        target=body.target,
        target_type=body.target_type,
        scope=body.scope,
        status="pending",
    )
    scan_run = ScanRun(
        round=1,
        scan_type="nmap",
        status="pending",
    )

    # targets + scan_runs must commit together; otherwise dispatcher has nothing to pick up.
    async with db.begin():
        db.add(target)
        await db.flush()
        scan_run.target_id = target.id
        db.add(scan_run)
        await db.flush()

    if scan_run.id is None or target.id is None:
        raise RuntimeError("POST /targets failed to create target and scan_run in one transaction")

    return TargetCreateResponse(        target_id=target.id,
        scan_run_id=scan_run.id,
        status=scan_run.status,
    )

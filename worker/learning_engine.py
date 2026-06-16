from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


DEFAULT_LEARNING_SCORE = 0.5


async def get_tool_learning_score(
    session: AsyncSession,
    tool_name: str | None,
) -> float:
    """
    Read final learning score from learning_tool_score view.

    Return:
        0.0 ~ 1.0
    """

    if not tool_name:
        return DEFAULT_LEARNING_SCORE

    result = await session.execute(
        text("""
            SELECT final_learning_score
            FROM learning_tool_score
            WHERE tool_name = :tool_name
        """),
        {"tool_name": tool_name},
    )

    row = result.first()

    if not row or row.final_learning_score is None:
        return DEFAULT_LEARNING_SCORE

    return float(row.final_learning_score)


async def get_learning_feedback(
    session: AsyncSession,
    tool_name: str | None,
) -> dict[str, float] | None:
    """
    Convert learning_tool_score view into v2.1/v3 compatible feedback format.

    calculate_risk_v21 expects:
        {
            "success_rate": float,
            "false_positive_rate": float
        }
    """

    if not tool_name:
        return None

    learning_score = await get_tool_learning_score(
        session=session,
        tool_name=tool_name,
    )

    return {
        "success_rate": learning_score,
        "false_positive_rate": 0.0,
    }


async def record_learning_feedback(
    session: AsyncSession,
    *,
    decision_id: int | None,
    tool_result_id: int | None,
    tool_name: str,
    service: str | None = None,
    evidence_type: str | None = None,
    recommended_action: str | None = None,
    success: bool | None = None,
    was_success: bool | None = None,
    confidence_delta: float = 0.0,
    learning_score: float = 0.5,
    reason: str | None = None,
    feedback: str | None = None,
) -> None:
    """
    Insert actual execution feedback into learning_feedback.
    """
    if success is None:
        success = was_success
    if success is None:
        success = False

    await session.execute(
        text("""
            INSERT INTO learning_feedback (
                decision_id,
                tool_result_id,
                tool_name,
                service,
                evidence_type,
                recommended_action,
                success,
                was_success,
                confidence_delta,
                learning_score,
                reason,
                feedback
            )
            VALUES (
                :decision_id,
                :tool_result_id,
                :tool_name,
                :service,
                :evidence_type,
                :recommended_action,
                :success,
                :was_success,
                :confidence_delta,
                :learning_score,
                :reason,
                :feedback
            )
        """),
        {
            "decision_id": decision_id,
            "tool_result_id": tool_result_id,
            "tool_name": tool_name,
            "service": service,
            "evidence_type": evidence_type,
            "recommended_action": recommended_action,
            "success": success,
            "was_success": was_success if was_success is not None else success,
            "confidence_delta": confidence_delta,
            "learning_score": learning_score,
            "reason": reason,
            "feedback": feedback or reason,
        },
    )

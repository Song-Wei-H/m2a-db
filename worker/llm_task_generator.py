from __future__ import annotations

import asyncio

from sqlalchemy import select, update

from app.database import async_session
from app.models import DecisionScore, LlmRecommendation, ToolTask
from app.tool_task_writer import create_tool_task_if_not_exists


ALLOWED_ACTIONS_TO_TASK = {"verify", "continue"}


async def generate_task_from_llm_recommendation(
    recommendation_id: int,
) -> int | None:
    async with async_session() as db, db.begin():
        recommendation = await db.get(LlmRecommendation, recommendation_id)

        if recommendation is None:
            raise ValueError(f"llm_recommendation_id={recommendation_id} not found")

        if not recommendation.approved:
            return None

        if recommendation.validator_status not in {"accepted", "overridden"}:
            return None

        if recommendation.recommended_action not in ALLOWED_ACTIONS_TO_TASK:
            return None

        if not recommendation.recommended_tool:
            return None

        decision = await db.get(DecisionScore, recommendation.decision_score_id)

        if decision is None:
            raise ValueError(
                f"decision_score_id={recommendation.decision_score_id} not found"
            )

        exists = (
            await db.execute(
                select(ToolTask).where(
                    ToolTask.target_id == recommendation.target_id,
                    ToolTask.open_port_id == decision.open_port_id,
                    ToolTask.tool_name == recommendation.recommended_tool,
                    ToolTask.status.in_(["pending", "running", "completed"]),
                )
            )
        ).scalar_one_or_none()

        if exists:
            return exists.id

        task, _ = await create_tool_task_if_not_exists(
            db,
            target_id=recommendation.target_id,
            open_port_id=decision.open_port_id,
            decision_score_id=decision.id,
            tool_name=recommendation.recommended_tool,
            status="pending",
            priority=80,
            approval_required=True,
            approval_status="pending_approval",
            approval_reason=(
                f"LLM recommended {recommendation.recommended_action} "
                f"with {recommendation.recommended_tool}; "
                f"confidence={recommendation.confidence}; "
                f"recommendation_id={recommendation.id}"
            ),
        )

        return task.id if task else None


async def generate_latest_approved() -> int | None:
    async with async_session() as db:
        result = await db.execute(
            select(LlmRecommendation)
            .where(
                LlmRecommendation.approved.is_(True),
                LlmRecommendation.recommended_tool.is_not(None),
            )
            .order_by(LlmRecommendation.id.desc())
            .limit(1)
        )

        recommendation = result.scalar_one_or_none()

    if recommendation is None:
        return None

    return await generate_task_from_llm_recommendation(recommendation.id)


def main() -> None:
    task_id = asyncio.run(generate_latest_approved())

    if task_id is None:
        print("no approved LLM recommendation to generate task")
    else:
        print(f"generated tool_task.id={task_id}")


if __name__ == "__main__":
    main()

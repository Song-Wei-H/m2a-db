"""Async statistics provider for advisory learning decisions."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from worker.learning_context import LearningContext


DEFAULT_SUCCESS_RATE = 0.5
DEFAULT_LEARNING_SCORE = 0.5


class LearningStatisticsProvider:
    """Read-only statistics access over learning feedback views.

    This class intentionally contains no ML model, training, persistence, or
    prediction. It only exposes aggregate statistics for ranking strategies.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_tool_statistics(self, context: LearningContext) -> dict[str, dict[str, Any]]:
        result = await self.session.execute(
            text(
                """
                SELECT
                    tool_name,
                    service,
                    evidence_type,
                    port_bucket,
                    total_runs,
                    success_count,
                    failure_count,
                    success_rate,
                    avg_learning_score,
                    last_seen
                FROM learning_tool_context_score
                WHERE (:service IS NULL OR service = :service)
                  AND (:evidence_type IS NULL OR evidence_type = :evidence_type)
                  AND (:port_bucket IS NULL OR port_bucket = :port_bucket)
                """
            ),
            {
                "service": context.service,
                "evidence_type": context.evidence_type,
                "port_bucket": context.port_bucket,
            },
        )
        rows = result.fetchall()
        return {_mapping(row)["tool_name"]: dict(_mapping(row)) for row in rows}

    async def get_context_statistics(self, context: LearningContext) -> dict[str, Any]:
        tool_stats = await self.get_tool_statistics(context)
        total_runs = sum(int(row.get("total_runs") or 0) for row in tool_stats.values())
        success_count = sum(int(row.get("success_count") or 0) for row in tool_stats.values())
        scores = [
            float(row["avg_learning_score"])
            for row in tool_stats.values()
            if row.get("avg_learning_score") is not None
        ]
        return {
            "tool_count": len(tool_stats),
            "total_runs": total_runs,
            "success_rate": success_count / total_runs if total_runs else DEFAULT_SUCCESS_RATE,
            "avg_learning_score": sum(scores) / len(scores) if scores else DEFAULT_LEARNING_SCORE,
        }

    async def get_tool_success_rate(self, tool_name: str, context: LearningContext | None = None) -> float:
        row = await self._get_tool_row(tool_name, context)
        if row is None or row.get("success_rate") is None:
            return DEFAULT_SUCCESS_RATE
        return float(row["success_rate"])

    async def get_average_learning_score(self, tool_name: str, context: LearningContext | None = None) -> float:
        row = await self._get_tool_row(tool_name, context)
        if row is None or row.get("avg_learning_score") is None:
            return DEFAULT_LEARNING_SCORE
        return float(row["avg_learning_score"])

    async def get_recent_learning(self, tool_name: str, limit: int = 5) -> dict[str, Any]:
        result = await self.session.execute(
            text(
                """
                SELECT learning_score, success, created_at
                FROM learning_feedback
                WHERE tool_name = :tool_name
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"tool_name": tool_name, "limit": limit},
        )
        rows = [dict(_mapping(row)) for row in result.fetchall()]
        scores = [float(row["learning_score"]) for row in rows if row.get("learning_score") is not None]
        return {
            "recent_count": len(rows),
            "recent_score": sum(scores) / len(scores) if scores else DEFAULT_LEARNING_SCORE,
            "rows": rows,
        }

    async def get_total_observations(self, context: LearningContext | None = None) -> int:
        if context is None:
            result = await self.session.execute(text("SELECT COUNT(*) AS count FROM learning_feedback"))
            row = result.first()
            return int(_mapping(row).get("count") or 0) if row else 0
        stats = await self.get_context_statistics(context)
        return int(stats["total_runs"])

    async def _get_tool_row(self, tool_name: str, context: LearningContext | None) -> dict[str, Any] | None:
        if context is None:
            result = await self.session.execute(
                text(
                    """
                    SELECT
                        tool_name,
                        COUNT(*)::INT AS total_runs,
                        COUNT(*) FILTER (WHERE success IS TRUE)::INT AS success_count,
                        CASE WHEN COUNT(*) = 0 THEN 0.5
                             ELSE COUNT(*) FILTER (WHERE success IS TRUE)::FLOAT / COUNT(*)::FLOAT
                        END AS success_rate,
                        COALESCE(AVG(learning_score), 0.5)::FLOAT AS avg_learning_score,
                        MAX(created_at) AS last_seen
                    FROM learning_feedback
                    WHERE tool_name = :tool_name
                    GROUP BY tool_name
                    """
                ),
                {"tool_name": tool_name},
            )
            row = result.first()
            return dict(_mapping(row)) if row else None

        stats = await self.get_tool_statistics(context)
        return stats.get(tool_name)


def _mapping(row: Any) -> dict[str, Any]:
    if row is None:
        return {}
    if hasattr(row, "_mapping"):
        return dict(row._mapping)
    if isinstance(row, dict):
        return row
    return dict(row)

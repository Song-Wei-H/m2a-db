from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from app.models import ToolResult
import worker.learning_engine as learning_engine

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

LEARNING_SCORE_SUCCESS = 0.70
LEARNING_SCORE_FAILURE = 0.30

USEFUL_EVIDENCE_ADJUSTMENT = 0.15
HIGH_CONFIDENCE_ADJUSTMENT = 0.10
EMPTY_PARSED_OUTPUT_ADJUSTMENT = -0.20
TIMEOUT_ADJUSTMENT = -0.20
BLOCKED_ADJUSTMENT = -0.25

REASON_SUCCESS = "Tool executed successfully."
REASON_FAILURE = "Tool execution failed."


def _has_parser_evidence(parsed_output: Any) -> bool:
    if not parsed_output:
        return False
    if not isinstance(parsed_output, dict):
        return True

    nested = parsed_output.get("parsed_result")
    if isinstance(nested, dict) and _has_parser_evidence(nested):
        return True

    if "finding_count" in parsed_output:
        return True
    if parsed_output.get("findings"):
        return True
    if parsed_output.get("open_ports"):
        return True
    if parsed_output.get("status_codes"):
        return True
    if parsed_output.get("evidence_type") or parsed_output.get("type"):
        return True

    return any(value not in (None, "", 0) and value != [] and value != {} for value in parsed_output.values())


def _clamp_score(value: float) -> float:
    return round(max(0.0, min(value, 1.0)), 4)


def _is_empty_parsed_output(parsed_output: Any) -> bool:
    return not isinstance(parsed_output, dict) or not parsed_output


def _actual_confidence(tool_result: ToolResult, fallback: float = 0.5) -> float:
    parsed_output = getattr(tool_result, "parsed_output", None)
    if isinstance(parsed_output, dict):
        for key in ("confidence_score", "confidence"):
            value = parsed_output.get(key)
            if value is not None:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    pass
    return fallback


def _has_high_confidence_evidence(tool_result: ToolResult) -> bool:
    return _actual_confidence(tool_result) >= 0.8


def _has_evidence(tool_result: ToolResult) -> bool:
    evidence = getattr(tool_result, "evidence", None)
    raw_output = getattr(tool_result, "raw_output", None)
    return bool(
        (isinstance(evidence, str) and evidence.strip())
        or (isinstance(raw_output, str) and raw_output.strip())
        or _has_parser_evidence(getattr(tool_result, "parsed_output", None))
    )


def _has_useful_evidence(tool_result: ToolResult) -> bool:
    parsed_output = getattr(tool_result, "parsed_output", None)
    if _has_parser_evidence(parsed_output):
        return True
    if not tool_result.success:
        return False
    evidence = getattr(tool_result, "evidence", None)
    raw_output = getattr(tool_result, "raw_output", None)
    return bool(
        (isinstance(evidence, str) and evidence.strip())
        or (isinstance(raw_output, str) and raw_output.strip())
    )


def calculate_learning_score(tool_result: ToolResult) -> tuple[float, str]:
    """Calculate deterministic learning score for a completed ToolResult."""
    has_evidence = _has_useful_evidence(tool_result)
    status = get_tool_result_status(tool_result)
    parsed_output = getattr(tool_result, "parsed_output", None)
    score = LEARNING_SCORE_SUCCESS if tool_result.success else LEARNING_SCORE_FAILURE
    reasons = [REASON_SUCCESS if tool_result.success else REASON_FAILURE]

    if has_evidence:
        score += USEFUL_EVIDENCE_ADJUSTMENT
        reasons.append("Useful evidence found.")

    if _has_high_confidence_evidence(tool_result):
        score += HIGH_CONFIDENCE_ADJUSTMENT
        reasons.append("High confidence evidence.")

    if _is_empty_parsed_output(parsed_output):
        score += EMPTY_PARSED_OUTPUT_ADJUSTMENT
        reasons.append("Empty parsed output.")

    if status == "timeout":
        score += TIMEOUT_ADJUSTMENT
        reasons.append("Timeout observed.")

    if status == "blocked":
        score += BLOCKED_ADJUSTMENT
        reasons.append("Blocked execution observed.")

    return _clamp_score(score), " ".join(reasons)


def calculate_confidence_delta(
    *,
    expected_confidence: float | None,
    actual_outcome_confidence: float | None,
) -> float:
    expected = 0.0 if expected_confidence is None else float(expected_confidence)
    actual = 0.0 if actual_outcome_confidence is None else float(actual_outcome_confidence)
    return round(actual - expected, 4)


def determine_evidence_type(tool_result: ToolResult) -> str | None:
    """Determine the evidence type based on the tool result."""
    parsed_output = tool_result.parsed_output
    if not isinstance(parsed_output, dict):
        return None

    if parsed_output.get("evidence_type") or parsed_output.get("type"):
        return parsed_output.get("evidence_type") or parsed_output.get("type")
    if parsed_output.get("finding_count") is not None or parsed_output.get("findings") is not None:
        return "vulnerability_scan"
    if parsed_output.get("open_ports") is not None:
        return "open_ports"
    if parsed_output.get("status_codes") is not None:
        return "http_probe"
    if parsed_output.get("error"):
        return "execution_error"
    return None


def determine_service(tool_result: ToolResult, service: str | None = None) -> str | None:
    """Extract service information from context first, then parsed output."""
    if service:
        return service

    parsed_output = tool_result.parsed_output
    if isinstance(parsed_output, dict):
        return (
            parsed_output.get("service")
            or parsed_output.get("protocol")
            or parsed_output.get("tool")
            or tool_result.tool_name
        )
    return tool_result.tool_name


def determine_recommended_action(tool_result: ToolResult, recommended_action: str | None = None) -> str | None:
    if recommended_action:
        return recommended_action

    parsed_output = tool_result.parsed_output
    if isinstance(parsed_output, dict):
        action = parsed_output.get("recommended_action") or parsed_output.get("next_action")
        if action:
            return action

    return "verify" if not tool_result.success else None


async def create_learning_feedback(
    session: AsyncSession,
    tool_result: ToolResult,
    *,
    decision_id: int | None = None,
    service: str | None = None,
    evidence_type: str | None = None,
    recommended_action: str | None = None,
    confidence_delta: float | None = None,
    expected_confidence: float | None = None,
    actual_outcome_confidence: float | None = None,
) -> None:
    """
    Create a LearningFeedback record based on a ToolResult.

    This function is designed to never break the execution flow.
    If there's an exception, it will be logged and ignored.
    """
    try:
        learning_score, reason = calculate_learning_score(tool_result)
        resolved_evidence_type = evidence_type or determine_evidence_type(tool_result)
        resolved_service = determine_service(tool_result, service)
        resolved_action = determine_recommended_action(tool_result, recommended_action)
        resolved_confidence_delta = (
            confidence_delta
            if confidence_delta is not None
            else calculate_confidence_delta(
                expected_confidence=expected_confidence,
                actual_outcome_confidence=actual_outcome_confidence
                if actual_outcome_confidence is not None
                else _actual_confidence(tool_result),
            )
        )

        await learning_engine.record_learning_feedback(
            session=session,
            decision_id=decision_id,
            tool_result_id=tool_result.id,
            tool_name=tool_result.tool_name or "",
            service=resolved_service,
            evidence_type=resolved_evidence_type,
            recommended_action=resolved_action,
            success=tool_result.success,
            was_success=tool_result.success,
            confidence_delta=resolved_confidence_delta,
            learning_score=learning_score,
            reason=reason,
            feedback=reason,
        )
    except Exception as exc:
        logger.exception(
            "Failed to create learning feedback for tool_result_id=%s: %s",
            tool_result.id,
            str(exc),
        )


def get_tool_result_status(tool_result: ToolResult) -> str:
    """Determine the status of the tool result for scoring purposes."""
    if tool_result.success:
        return "success"
    if tool_result.evidence and "timeout" in tool_result.evidence.lower():
        return "timeout"
    if tool_result.evidence and "forbidden" in tool_result.evidence.lower():
        return "blocked"
    if tool_result.evidence and "not_found" in tool_result.evidence.lower():
        return "not_found"
    return "failed"

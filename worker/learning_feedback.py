from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.models import ToolResult, LearningFeedback
from worker.learning_engine import record_learning_feedback

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Learning score rules
LEARNING_SCORE_SUCCESS = 1.0
LEARNING_SCORE_SUCCESS_WITH_EVIDENCE = 1.5
LEARNING_SCORE_FAILURE = -1.0
LEARNING_SCORE_TIMEOUT = -2.0
LEARNING_SCORE_BLOCKED = -2.0
LEARNING_SCORE_UNKNOWN = 0.0

# Reason messages
REASON_SUCCESS_EVIDENCE = "Tool executed successfully and produced evidence."
REASON_SUCCESS_NO_EVIDENCE = "Tool executed successfully."
REASON_FAILURE = "Tool execution failed."
REASON_TIMEOUT = "Tool execution timed out."
REASON_BLOCKED = "Tool execution blocked by policy."
REASON_UNKNOWN = "Tool result could not be classified."


def calculate_learning_score(tool_result: ToolResult) -> tuple[float, str]:
    """
    Calculate the learning score based on deterministic rules and determine the appropriate reason.
    
    Returns:
        tuple of (learning_score, reason)
    """
    # Default values
    learning_score = LEARNING_SCORE_UNKNOWN
    reason = REASON_UNKNOWN
    
    # Determine the result type and set appropriate score and reason
    if tool_result.success:
        # Check if there's evidence in the parsed output
        has_evidence = False
        if tool_result.parsed_output:
            # Check for evidence of findings in the parsed output
            parsed_output = tool_result.parsed_output
            if isinstance(parsed_output, dict):
                # Check for evidence in various tool outputs
                if "parsed_result" in parsed_output:
                    parsed_data = parsed_output.get("parsed_result", {})
                    if parsed_data and isinstance(parsed_data, dict):
                        if "finding_count" in parsed_data and parsed_data.get("finding_count", 0) > 0:
                            has_evidence = True
                        elif "findings" in parsed_data and len(parsed_data.get("findings", [])) > 0:
                            has_evidence = True
                        elif "status" in parsed_output and parsed_output["status"] == "done":
                            has_evidence = True
                elif "status" in parsed_output and parsed_output["status"] == "done":
                    has_evidence = True
        
        if has_evidence:
            learning_score = LEARNING_SCORE_SUCCESS_WITH_EVIDENCE
            reason = REASON_SUCCESS_EVIDENCE
        else:
            learning_score = LEARNING_SCORE_SUCCESS
            reason = REASON_SUCCESS_NO_EVIDENCE
    else:
        # Determine the type of failure
        if tool_result.evidence and "timeout" in tool_result.evidence.lower():
            learning_score = LEARNING_SCORE_TIMEOUT
            reason = REASON_TIMEOUT
        elif tool_result.evidence and "forbidden" in tool_result.evidence.lower():
            learning_score = LEARNING_SCORE_BLOCKED
            reason = REASON_BLOCKED
        elif tool_result.evidence and "not_found" in tool_result.evidence.lower():
            learning_score = LEARNING_SCORE_FAILURE
            reason = REASON_FAILURE
        else:
            learning_score = LEARNING_SCORE_FAILURE
            reason = REASON_FAILURE
            
    return learning_score, reason


def determine_evidence_type(tool_result: ToolResult) -> str | None:
    """
    Determine the evidence type based on the tool result.
    """
    if not tool_result.parsed_output:
        return None
        
    parsed_output = tool_result.parsed_output
    if isinstance(parsed_output, dict):
        return parsed_output.get("evidence_type") or parsed_output.get("type")
    return None


def determine_service(tool_result: ToolResult) -> str | None:
    """
    Extract service information from the tool result.
    """
    if tool_result.parsed_output and isinstance(tool_result.parsed_output, dict):
        return (
            tool_result.parsed_output.get("service") or 
            tool_result.parsed_output.get("tool") or
            tool_result.tool_name
        )
    return tool_result.tool_name


async def create_learning_feedback(
    session: AsyncSession,
    tool_result: ToolResult,
) -> None:
    """
    Create a LearningFeedback record based on a ToolResult.
    
    This function is designed to never break the execution flow.
    If there's an exception, it will be logged and ignored.
    """
    try:
        # Calculate learning score and reason
        learning_score, reason = calculate_learning_score(tool_result)
        
        # Determine evidence type
        evidence_type = determine_evidence_type(tool_result)
        
        # Determine service
        service = determine_service(tool_result)
        
        # Create the learning feedback record
        await record_learning_feedback(
            session=session,
            decision_id=None,
            tool_result_id=tool_result.id,
            tool_name=tool_result.tool_name or "",
            service=service,
            evidence_type=evidence_type,
            recommended_action="verify" if not tool_result.success else None,
            success=tool_result.success,
            learning_score=learning_score,
            reason=reason,
            feedback=reason,
        )
    except Exception as e:
        # Log exception but continue processing
        logger.exception("Failed to create learning feedback for tool_result_id=%s: %s", tool_result.id, str(e))
        # Do not raise the exception to avoid breaking execution flow


def get_tool_result_status(tool_result: ToolResult) -> str:
    """
    Determine the status of the tool result for scoring purposes.
    """
    if tool_result.success:
        return "success"
    elif tool_result.evidence and "timeout" in tool_result.evidence:
        return "timeout"
    elif tool_result.evidence and "forbidden" in tool_result.evidence:
        return "blocked"
    elif tool_result.evidence and "not_found" in tool_result.evidence:
        return "not_found"
    else:
        return "failed"
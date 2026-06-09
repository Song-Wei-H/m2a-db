# worker/llm_validator.py

from __future__ import annotations

ALLOWED_ACTIONS = {
    "stop",
    "continue",
    "verify",
    "remediate",
}

ALLOWED_TOOLS = {
    None,
    "nmap_service",
    "httpx_basic",
    "nuclei_safe",
    "dirb_safe",
}


def validate_recommendation(
    recommendation: dict,
    *,
    match_confidence: float | None = None,
    httpx_enabled: bool = False,
) -> dict:

    result = recommendation.copy()

    action = result.get("recommended_action")
    tool = result.get("recommended_tool")

    # Rule 1
    if action not in ALLOWED_ACTIONS:
        raise ValueError(
            f"Invalid action: {action}"
        )

    # Rule 2
    if tool not in ALLOWED_TOOLS:
        raise ValueError(
            f"Invalid tool: {tool}"
        )

    # Rule 3
    if (
        match_confidence is not None
        and match_confidence < 0.7
        and action == "remediate"
    ):
        result["recommended_action"] = "verify"

        if not result.get("recommended_tool"):
            result["recommended_tool"] = "nuclei_safe"

    # Rule 4
    if (
        tool == "httpx_basic"
        and not httpx_enabled
    ):
        result["recommended_action"] = "verify"
        result["recommended_tool"] = "nuclei_safe"

    # Rule 5
    if result["recommended_action"] in {
        "stop",
        "remediate",
    }:
        result["recommended_tool"] = None

    return result
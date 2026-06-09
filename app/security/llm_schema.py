"""LLM may only emit this JSON shape — never shell commands."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal["info", "low", "medium", "high", "critical"]


class LlmToolProposal(BaseModel):
    """
    Strict LLM output contract.
    Extra fields (command, shell, raw_command, …) are rejected.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(..., min_length=1, max_length=100)
    target: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(..., min_length=1, max_length=2000)
    risk_level: RiskLevel

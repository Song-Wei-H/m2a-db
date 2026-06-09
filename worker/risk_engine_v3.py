from __future__ import annotations

from typing import Any

from worker.risk_engine_v2 import RiskV21Result, calculate_risk_v21


def calculate_risk_v3(
    *,
    target_id: int,
    open_port_id: int | None,
    service: str | None,
    port: int | None,
    cvss: float | None,
    epss: float | None,
    kev: bool,
    tool_name: str,
    parsed_output: dict[str, Any],
    raw_output: str = "",
    base_confidence: float = 0.7,
    learning_feedback: dict[str, Any] | None = None,
) -> RiskV21Result:
    """
    Risk Engine v3 = Risk Engine v2.1 + Learning Feedback.

    This wrapper keeps the same interface as calculate_risk_v21,
    so analysis_pipeline.py can migrate with minimal changes.
    """

    return calculate_risk_v21(
        target_id=target_id,
        open_port_id=open_port_id,
        service=service,
        port=port,
        cvss=cvss,
        epss=epss,
        kev=kev,
        tool_name=tool_name,
        parsed_output=parsed_output,
        raw_output=raw_output,
        base_confidence=base_confidence,
        learning_feedback=learning_feedback,
    )
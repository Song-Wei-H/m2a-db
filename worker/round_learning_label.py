"""Round value labels for future supervised learning datasets."""

from __future__ import annotations

from dataclasses import asdict, dataclass


LABEL_VERSION = "round-label-v1"


@dataclass(frozen=True)
class RoundLearningLabel:
    target_id: int
    scan_run_id: int | None
    round_number: int
    tool_name: str | None
    service: str | None
    evidence_type: str | None
    current_risk: float | None
    next_risk: float | None
    current_confidence: float | None
    next_confidence: float | None
    new_findings: int
    new_cve: int
    new_open_port: int
    evidence_delta: int
    learning_score: float | None
    round_value: float

    def to_dict(self) -> dict:
        return asdict(self)

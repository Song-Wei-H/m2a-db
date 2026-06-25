import pytest

from worker.round_label_builder import (
    RoundValueLabelBuilder,
    build_round_learning_label,
    persist_round_learning_label,
)
from worker.round_learning_label import LABEL_VERSION


class FakeSession:
    def __init__(self):
        self.calls = []

    async def execute(self, statement, params=None):
        self.calls.append((str(statement), params or {}))


def test_round_label_builder_generates_label_from_state_delta():
    label = build_round_learning_label(
        target_id=1,
        scan_run_id=None,
        round_number=2,
        tool_name="nuclei_safe",
        current_state={
            "finding_count": 1,
            "cve_count": 0,
            "open_port_count": 1,
            "evidence_count": 2,
            "risk_score": 4.0,
            "confidence": 0.5,
            "service": "https",
        },
        next_state={
            "finding_count": 2,
            "cve_count": 1,
            "open_port_count": 1,
            "evidence_count": 4,
            "risk_score": 7.0,
            "confidence": 0.8,
            "learning_score": 0.9,
            "evidence_type": "vulnerability",
        },
    )

    assert label.target_id == 1
    assert label.round_number == 2
    assert label.tool_name == "nuclei_safe"
    assert label.service == "https"
    assert label.evidence_type == "vulnerability"
    assert label.new_findings == 1
    assert label.new_cve == 1
    assert label.evidence_delta == 2
    assert label.round_value == 5


def test_round_value_label_builder_class_wraps_label_generation():
    builder = RoundValueLabelBuilder()
    label = builder.build_label(
        target_id=7,
        scan_run_id=None,
        round_number=1,
        tool_name="nuclei_safe",
        current_state={"finding_count": 0},
        next_state={"finding_count": 1},
    )

    assert label.target_id == 7
    assert label.tool_name == "nuclei_safe"
    assert label.round_value == 1


def test_round_label_builder_penalizes_duplicate_timeout():
    label = build_round_learning_label(
        target_id=1,
        round_number=3,
        tool_name="dirb_safe",
        current_state={"finding_count": 1, "evidence_count": 2},
        next_state={
            "finding_count": 1,
            "evidence_count": 2,
            "tool_timeout": True,
            "duplicate_finding": True,
        },
    )

    assert label.round_value == -2


@pytest.mark.asyncio
async def test_persist_round_learning_label_writes_schema_fields():
    session = FakeSession()
    label = build_round_learning_label(
        target_id=1,
        round_number=1,
        tool_name="httpx_basic",
        current_state={},
        next_state={"finding_count": 1},
    )

    await persist_round_learning_label(session, label)

    sql, params = session.calls[0]
    assert "round_learning_labels" in sql
    assert params["label_version"] == LABEL_VERSION
    assert params["round_value"] == label.round_value

"""Rule-based round value label builder.

No prediction or model training happens here. The builder only compares a round
state with the next observed state and emits labels for future datasets.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from worker.round_learning_label import LABEL_VERSION, RoundLearningLabel


class RoundValueLabelBuilder:
    """Build and persist rule-based round labels without making decisions."""

    def build_label(
        self,
        *,
        target_id: int,
        round_number: int,
        tool_name: str | None,
        current_state: dict[str, Any],
        next_state: dict[str, Any],
        scan_run_id: int | None = None,
    ) -> RoundLearningLabel:
        return build_round_learning_label(
            target_id=target_id,
            scan_run_id=scan_run_id,
            round_number=round_number,
            tool_name=tool_name,
            current_state=current_state,
            next_state=next_state,
        )

    async def persist(self, session: AsyncSession, label: RoundLearningLabel) -> None:
        await persist_round_learning_label(session, label)


def calculate_round_value(
    *,
    new_findings: int = 0,
    new_cve: int = 0,
    new_critical: int = 0,
    risk_increase: bool = False,
    confidence_increase: bool = False,
    tool_timeout: bool = False,
    duplicate_finding: bool = False,
    no_change: bool = False,
) -> float:
    value = 0.0
    value += new_findings * 1
    value += new_cve * 2
    value += new_critical * 3
    if risk_increase:
        value += 1
    if confidence_increase:
        value += 1
    if tool_timeout:
        value -= 1
    if duplicate_finding:
        value -= 1
    if no_change and value == 0:
        return 0.0
    return value


def build_round_learning_label(
    *,
    target_id: int,
    round_number: int,
    tool_name: str | None,
    current_state: dict[str, Any],
    next_state: dict[str, Any],
    scan_run_id: int | None = None,
) -> RoundLearningLabel:
    current_findings = int(current_state.get("finding_count") or 0)
    next_findings = int(next_state.get("finding_count") or 0)
    current_cve = int(current_state.get("cve_count") or 0)
    next_cve = int(next_state.get("cve_count") or 0)
    current_ports = int(current_state.get("open_port_count") or 0)
    next_ports = int(next_state.get("open_port_count") or 0)
    current_evidence = int(current_state.get("evidence_count") or 0)
    next_evidence = int(next_state.get("evidence_count") or 0)

    current_risk = _float_or_none(current_state.get("risk_score"))
    next_risk = _float_or_none(next_state.get("risk_score"))
    current_confidence = _float_or_none(current_state.get("confidence"))
    next_confidence = _float_or_none(next_state.get("confidence"))

    new_findings = max(next_findings - current_findings, 0)
    new_cve = max(next_cve - current_cve, 0)
    new_open_port = max(next_ports - current_ports, 0)
    evidence_delta = next_evidence - current_evidence
    new_critical = max(int(next_state.get("critical_count") or 0) - int(current_state.get("critical_count") or 0), 0)
    risk_increase = current_risk is not None and next_risk is not None and next_risk > current_risk
    confidence_increase = (
        current_confidence is not None
        and next_confidence is not None
        and next_confidence > current_confidence
    )
    tool_timeout = bool(next_state.get("tool_timeout"))
    duplicate_finding = bool(next_state.get("duplicate_finding"))
    no_change = new_findings == 0 and new_cve == 0 and new_open_port == 0 and evidence_delta == 0

    return RoundLearningLabel(
        target_id=target_id,
        scan_run_id=scan_run_id,
        round_number=round_number,
        tool_name=tool_name,
        service=next_state.get("service") or current_state.get("service"),
        evidence_type=next_state.get("evidence_type") or current_state.get("evidence_type"),
        current_risk=current_risk,
        next_risk=next_risk,
        current_confidence=current_confidence,
        next_confidence=next_confidence,
        new_findings=new_findings,
        new_cve=new_cve,
        new_open_port=new_open_port,
        evidence_delta=evidence_delta,
        learning_score=_float_or_none(next_state.get("learning_score")),
        round_value=calculate_round_value(
            new_findings=new_findings,
            new_cve=new_cve,
            new_critical=new_critical,
            risk_increase=risk_increase,
            confidence_increase=confidence_increase,
            tool_timeout=tool_timeout,
            duplicate_finding=duplicate_finding,
            no_change=no_change,
        ),
    )


async def persist_round_learning_label(
    session: AsyncSession,
    label: RoundLearningLabel,
) -> None:
    data = label.to_dict()
    data["label_version"] = LABEL_VERSION
    await session.execute(
        text(
            """
            INSERT INTO round_learning_labels (
                target_id,
                scan_run_id,
                round_number,
                tool_name,
                service,
                evidence_type,
                current_risk,
                next_risk,
                current_confidence,
                next_confidence,
                new_findings,
                new_cve,
                new_open_port,
                evidence_delta,
                learning_score,
                round_value,
                label_version
            )
            VALUES (
                :target_id,
                :scan_run_id,
                :round_number,
                :tool_name,
                :service,
                :evidence_type,
                :current_risk,
                :next_risk,
                :current_confidence,
                :next_confidence,
                :new_findings,
                :new_cve,
                :new_open_port,
                :evidence_delta,
                :learning_score,
                :round_value,
                :label_version
            )
            """
        ),
        data,
    )


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

from __future__ import annotations

import logging
from typing import Any

from worker.risk_engine_v2 import (
    HTTP_PORTS,
    RiskV21Result,
    calculate_risk_v21,
    clamp,
    clamp_confidence,
    decide_next_action,
    detect_runtime_signals,
    select_next_tool,
)

logger = logging.getLogger(__name__)

SEVERITY_THRESHOLDS = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
}


def severity_from_adjusted_score(score: float) -> str:
    if score >= SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    if score >= SEVERITY_THRESHOLDS["high"]:
        return "high"
    if score >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    if score >= SEVERITY_THRESHOLDS["low"]:
        return "low"
    return "info"


def _service_exposure_score(service: str | None, port: int | None) -> tuple[float, str]:
    service_name = (service or "").lower()

    if service_name in {"http", "https", "http-alt", "ssl/http"} or port in HTTP_PORTS:
        return 2.0, "HTTP-like exposed service adds base risk 2.0"
    if service_name == "ssh" or port == 22:
        return 1.5, "SSH exposed service adds base risk 1.5"
    if service_name in {"mysql", "mariadb", "postgresql", "microsoft sql"} or port in {3306, 5432, 1433}:
        return 2.2, "Database exposed service adds base risk 2.2"
    if service or port:
        return 1.0, "Generic open service adds base risk 1.0"
    return 0.0, "No service exposure available"


def _calculate_base_risk_v3(
    *,
    service: str | None,
    port: int | None,
    cvss: float | None,
    epss: float | None,
    kev: bool,
) -> tuple[float, dict[str, Any], list[str]]:
    exposure_score, exposure_reason = _service_exposure_score(service, port)
    components: dict[str, Any] = {
        "service_exposure": exposure_score,
        "cvss": cvss,
        "epss": epss,
        "kev": bool(kev),
    }
    reasoning = [exposure_reason]
    score = exposure_score

    if cvss is not None:
        cvss_value = clamp(float(cvss))
        contribution = cvss_value * 0.55
        score += contribution
        components["cvss_contribution"] = round(contribution, 2)
        reasoning.append(f"CVSS {cvss_value} contributes {contribution:.2f}")

    if epss is not None:
        epss_value = clamp(float(epss), 0.0, 1.0)
        contribution = epss_value * 1.5
        score += contribution
        components["epss_contribution"] = round(contribution, 2)
        reasoning.append(f"EPSS {epss_value:.4f} contributes {contribution:.2f}")

    if kev:
        score += 1.5
        components["kev_contribution"] = 1.5
        reasoning.append("KEV match contributes 1.50")

    return round(clamp(score), 2), components, reasoning


def _has_useful_evidence(parsed_output: dict[str, Any]) -> bool:
    if not parsed_output:
        return False
    if parsed_output.get("parser_success") is False:
        return False
    for key in ("findings", "ports", "services", "paths", "ssh_algorithms", "mysql"):
        value = parsed_output.get(key)
        if isinstance(value, (list, dict)) and bool(value):
            return True
    return any(
        parsed_output.get(key) not in (None, "", [], {})
        for key in ("status_code", "status_codes", "title", "service", "port", "url", "urls", "host", "finding_count")
    )


def _first_http_status(parsed_output: dict[str, Any]) -> int | None:
    status_code = parsed_output.get("status_code")
    if isinstance(status_code, int):
        return status_code
    status_codes = parsed_output.get("status_codes")
    if isinstance(status_codes, list) and status_codes and isinstance(status_codes[0], int):
        return status_codes[0]
    return None


def _calculate_evidence_adjustment_v3(
    *,
    tool_name: str,
    parsed_output: dict[str, Any],
    base_confidence: float,
) -> tuple[float, dict[str, Any], list[str]]:
    adjustment = 0.0
    reasoning: list[str] = []
    components: dict[str, Any] = {
        "base_confidence": base_confidence,
        "tool_name": tool_name,
    }

    confidence_adjustment = (clamp_confidence(base_confidence) - 0.5) * 2.0
    adjustment += confidence_adjustment
    components["confidence_contribution"] = round(confidence_adjustment, 2)
    reasoning.append(f"Evidence confidence contributes {confidence_adjustment:.2f}")

    if parsed_output.get("parser_success") is False:
        adjustment -= 0.4
        reasoning.append("Parser failure reduces evidence adjustment 0.40")

    if not parsed_output:
        adjustment -= 0.5
        reasoning.append("Empty parsed output reduces evidence adjustment 0.50")
    elif _has_useful_evidence(parsed_output):
        adjustment += 0.5
        reasoning.append("Useful structured evidence increases risk 0.50")

    success = parsed_output.get("success")
    if success is False:
        adjustment -= 0.6
        reasoning.append("Negative tool outcome reduces risk 0.60")
    elif success is True:
        adjustment += 0.2
        reasoning.append("Successful tool outcome increases confidence in risk 0.20")

    finding_count = parsed_output.get("finding_count")
    if isinstance(finding_count, int) and finding_count > 0:
        contribution = min(2.5, finding_count * 0.8)
        adjustment += contribution
        reasoning.append(f"finding_count={finding_count} contributes {contribution:.2f}")

    return round(adjustment, 2), components, reasoning


def _calculate_runtime_adjustment_v3(
    *,
    waf_detected: bool,
    tool_blocked: bool,
    tool_timeout: bool,
) -> tuple[float, float, dict[str, Any], list[str]]:
    adjustment = 0.0
    confidence_multiplier = 1.0
    components = {
        "waf_detected": waf_detected,
        "tool_blocked": tool_blocked,
        "tool_timeout": tool_timeout,
    }
    reasoning: list[str] = []

    if waf_detected:
        adjustment -= 0.2
        confidence_multiplier *= 0.75
        reasoning.append("WAF signal lowers runtime score and confidence")
    if tool_blocked:
        adjustment -= 0.3
        confidence_multiplier *= 0.75
        reasoning.append("Blocked execution lowers runtime score and confidence")
    if tool_timeout:
        adjustment -= 0.5
        confidence_multiplier *= 0.65
        reasoning.append("Timeout lowers runtime score and confidence")

    return round(adjustment, 2), confidence_multiplier, components, reasoning


def _calculate_learning_adjustment_v3(
    learning_feedback: dict[str, Any] | None,
) -> tuple[float, dict[str, Any], list[str]]:
    if not learning_feedback:
        return 0.0, {"learning_score": None}, ["No learning feedback available"]

    score = learning_feedback.get("learning_score", learning_feedback.get("success_rate"))
    if score is None:
        return 0.0, {"learning_score": None}, ["Learning feedback missing score"]

    learning_score = float(score)
    if learning_score > 1:
        learning_score = learning_score / 100
    learning_score = clamp_confidence(learning_score)

    adjustment = round((learning_score - 0.5) * 1.0, 2)
    return (
        adjustment,
        {"learning_score": learning_score},
        [f"Learning score {learning_score:.2f} contributes {adjustment:.2f}"],
    )


def _calculate_risk_v3_primary(
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
    if not isinstance(parsed_output, dict):
        raise ValueError("parsed_output must be a dict")

    base_risk_score, base_components, base_reasoning = _calculate_base_risk_v3(
        service=service,
        port=port,
        cvss=cvss,
        epss=epss,
        kev=kev,
    )
    waf_detected, tool_blocked, tool_timeout, runtime_signal_reasoning = detect_runtime_signals(
        parsed_output=parsed_output,
        raw_output=raw_output,
    )
    runtime_adjustment, confidence_multiplier, runtime_components, runtime_reasoning = _calculate_runtime_adjustment_v3(
        waf_detected=waf_detected,
        tool_blocked=tool_blocked,
        tool_timeout=tool_timeout,
    )
    evidence_adjustment, evidence_components, evidence_reasoning = _calculate_evidence_adjustment_v3(
        tool_name=tool_name,
        parsed_output=parsed_output,
        base_confidence=base_confidence,
    )
    learning_adjustment, learning_components, learning_reasoning = _calculate_learning_adjustment_v3(
        learning_feedback
    )

    adjusted_risk_score = round(
        clamp(base_risk_score + runtime_adjustment + evidence_adjustment + learning_adjustment),
        2,
    )
    confidence_score = round(
        clamp_confidence((base_confidence + max(evidence_adjustment, 0.0) * 0.05) * confidence_multiplier),
        4,
    )
    severity = severity_from_adjusted_score(adjusted_risk_score)
    next_tool = select_next_tool(
        service=service,
        port=port,
        adjusted_risk_score=adjusted_risk_score,
    )
    if tool_name == "httpx_basic" and next_tool == "httpx_basic":
        next_tool = "nuclei_safe"

    next_action = decide_next_action(
        base_risk_score=base_risk_score,
        adjusted_risk_score=adjusted_risk_score,
        confidence_score=confidence_score,
        severity=severity,
        next_tool=next_tool,
        waf_detected=waf_detected,
        tool_blocked=tool_blocked,
        tool_timeout=tool_timeout,
        kev_detected=kev,
        max_epss=epss,
        cvss=cvss,
    )
    http_status = _first_http_status(parsed_output)
    if next_tool is None and tool_name == "httpx_basic" and http_status is not None and http_status >= 500:
        next_action = "verify"

    components = {
        "engine": "risk_engine_v3",
        "cvss": cvss,
        "epss": epss,
        "kev": bool(kev),
        "learning_score": learning_components.get("learning_score"),
        "confidence": confidence_score,
        "base": base_components,
        "evidence": evidence_components,
        "runtime": runtime_components,
    }
    cve_summary = parsed_output.get("cve_summary")
    if isinstance(cve_summary, dict):
        components.update(
            {
                "match_count": cve_summary.get("cve_count", 0),
                "match_type": cve_summary.get("best_match_type"),
                "match_confidence": cve_summary.get("best_match_confidence"),
                "best_cve": cve_summary.get("best_cve"),
            }
        )
    reasoning: list[Any] = [
        components,
        *base_reasoning,
        *runtime_signal_reasoning,
        *runtime_reasoning,
        *evidence_reasoning,
        *learning_reasoning,
        f"base_risk_score={base_risk_score}",
        f"adjusted_risk_score={adjusted_risk_score}",
        f"confidence_score={confidence_score}",
        f"severity={severity}",
        f"next_action={next_action}",
        f"next_tool={next_tool}",
    ]

    return RiskV21Result(
        target_id=target_id,
        open_port_id=open_port_id,
        base_risk_score=base_risk_score,
        adjusted_risk_score=adjusted_risk_score,
        risk_score=adjusted_risk_score,
        confidence_score=confidence_score,
        learning_adjustment=learning_adjustment,
        runtime_adjustment=runtime_adjustment,
        evidence_adjustment=evidence_adjustment,
        waf_detected=waf_detected,
        tool_blocked=tool_blocked,
        tool_timeout=tool_timeout,
        severity=severity,
        next_action=next_action,
        next_tool=next_tool,
        reasoning=reasoning,
    )


def calculate_risk(
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
    try:
        return _calculate_risk_v3_primary(
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
    except Exception as exc:
        logger.warning("Risk Engine v3 failed; falling back to v2.1: %s", exc, exc_info=True)
        fallback_parsed_output = parsed_output if isinstance(parsed_output, dict) else {}
        result = calculate_risk_v21(
            target_id=target_id,
            open_port_id=open_port_id,
            service=service,
            port=port,
            cvss=cvss,
            epss=epss,
            kev=kev,
            tool_name=tool_name,
            parsed_output=fallback_parsed_output,
            raw_output=raw_output,
            base_confidence=base_confidence,
            learning_feedback=learning_feedback,
        )
        return RiskV21Result(
            **{
                **result.__dict__,
                "reasoning": [
                    {"engine": "risk_engine_v2_fallback", "fallback_reason": str(exc)},
                    *result.reasoning,
                ],
            }
        )


def calculate_risk_v3(**kwargs: Any) -> RiskV21Result:
    return calculate_risk(**kwargs)

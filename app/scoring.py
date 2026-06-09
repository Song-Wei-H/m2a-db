"""Risk scoring from open ports, vulnerabilities, and CVE enrichment."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.mitre_rules import DEPTH_TOOLS, DISCOVERY_TOOLS

NEXT_ACTIONS = frozenset({"continue", "verify", "remediate", "stop"})

VERIFY_THRESHOLD = 6.0
CONTINUE_THRESHOLD = 3.0
CRITICAL_CVSS_FOR_REMEDIATE = 9.0

SERVICE_BASE_SCORE: dict[str, float] = {
    "ssh": 3.0,
    "http": 2.5,
    "https": 2.5,
    "mysql": 4.0,
    "ms-sql": 4.5,
    "rdp": 4.0,
    "ftp": 2.0,
}

TOOL_RISK_BOOST = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
    "info": 0.2,
}


@dataclass
class PortContext:
    id: int
    port: int | None
    protocol: str | None
    service: str | None
    product: str | None
    version: str | None


@dataclass
class VulnContext:
    cve: str | None
    severity: str | None
    cvss: float | None
    epss: float | None
    kev: bool
    mitre_tactic: str | None
    mitre_technique: str | None
    enrichment_cvss: float | None = None
    enrichment_epss: float | None = None
    enrichment_kev: bool = False
    enrichment_tactic: str | None = None
    enrichment_technique: str | None = None


@dataclass
class TargetAssessmentContext:
    target_id: int
    open_ports: list[PortContext] = field(default_factory=list)
    vulnerabilities: list[VulnContext] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)


def _effective_cvss(vuln: VulnContext) -> float:
    return (
        vuln.enrichment_cvss
        or vuln.cvss
        or _severity_to_cvss(vuln.severity)
        or 0.0
    )


def _effective_epss(vuln: VulnContext) -> float:
    if vuln.enrichment_epss is not None:
        return vuln.enrichment_epss
    return vuln.epss or 0.0


def _effective_kev(vuln: VulnContext) -> bool:
    return vuln.kev or vuln.enrichment_kev


def _severity_to_cvss(severity: str | None) -> float | None:
    if not severity:
        return None
    mapping = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "info": 0.5,
    }
    return mapping.get(severity.lower())


def score_vulnerability(vuln: VulnContext) -> float:
    cvss = _effective_cvss(vuln)
    epss = _effective_epss(vuln)
    score = cvss * 0.45 + epss * 10.0 * 0.35
    if _effective_kev(vuln):
        score += 2.5
    if vuln.enrichment_tactic or vuln.mitre_tactic:
        score += 0.5
    return min(score, 10.0)


def score_open_port(port: PortContext) -> float:
    svc = (port.service or "").lower().split("/")[0].split(":")[0]
    base = SERVICE_BASE_SCORE.get(svc, 1.5)
    if port.port in (22, 3306, 3389, 445):
        base += 0.5
    if port.product:
        base += 0.3
    return min(base, 6.0)


def score_tool_results(tool_results: list[dict]) -> float:
    boost = 0.0
    for row in tool_results:
        level = (row.get("risk_level") or "").lower()
        boost += TOOL_RISK_BOOST.get(level, 0.0)
    return min(boost, 3.0)


def compute_risk_score(ctx: TargetAssessmentContext) -> float:
    if not ctx.open_ports and not ctx.vulnerabilities:
        return 0.0

    port_scores = [score_open_port(p) for p in ctx.open_ports]
    vuln_scores = [score_vulnerability(v) for v in ctx.vulnerabilities]
    tool_boost = score_tool_results(ctx.tool_results)

    peak = 0.0
    if port_scores:
        peak = max(peak, max(port_scores))
    if vuln_scores:
        peak = max(peak, max(vuln_scores))

    aggregate = peak + tool_boost * 0.5
    if vuln_scores:
        aggregate = max(aggregate, sum(vuln_scores) / len(vuln_scores))

    any_kev = any(_effective_kev(v) for v in ctx.vulnerabilities)
    if any_kev:
        aggregate = max(aggregate, 7.5)

    return round(min(aggregate, 10.0), 2)


def has_kev_with_critical_cvss(vulnerabilities: list[VulnContext]) -> bool:
    """Rule 3: KEV and CVSS >= 9.0 on the same vulnerability."""
    for vuln in vulnerabilities:
        if _effective_kev(vuln) and _effective_cvss(vuln) >= CRITICAL_CVSS_FOR_REMEDIATE:
            return True
    return False


def decide_next_action(
    risk_score: float,
    *,
    next_tool: str,
    vulnerabilities: list[VulnContext],
) -> str:
    """
    Priority (after remediate / verify guards):
    1. Discovery tools (httpx, ssh-enum, mysql-info) → continue
    2. Depth tools (nuclei, dirb) → continue only if risk_score >= 3.0
    3. KEV + CVSS >= 9.0 → remediate
    4. risk_score >= 6.0 → verify
    5. risk_score >= 3.0 and next_tool != none → continue
    6. otherwise → stop
    """
    # Rule 3 — critical exposure overrides low-score discovery routing.
    if has_kev_with_critical_cvss(vulnerabilities):
        return "remediate"

    # Rule 4
    if risk_score >= VERIFY_THRESHOLD:
        return "verify"

    # Rule 1 — initial safe enumeration always continues.
    if next_tool in DISCOVERY_TOOLS:
        return "continue"

    # Rule 2 — validation / deep scan needs minimum risk.
    if next_tool in DEPTH_TOOLS:
        if risk_score >= CONTINUE_THRESHOLD:
            return "continue"
        return "stop"

    # Rule 5
    if risk_score >= CONTINUE_THRESHOLD and next_tool != "none":
        return "continue"

    # Rule 6
    return "stop"


def compute_confidence(ctx: TargetAssessmentContext) -> float:
    score = 0.45
    if ctx.open_ports:
        score += min(0.25, 0.05 * len(ctx.open_ports))
    if ctx.vulnerabilities:
        score += 0.15
    if any(v.enrichment_cvss is not None or v.enrichment_epss is not None for v in ctx.vulnerabilities):
        score += 0.15
    return round(min(score, 0.95), 2)


def pick_focus_port(ctx: TargetAssessmentContext) -> PortContext | None:
    if not ctx.open_ports:
        return None
    return max(ctx.open_ports, key=lambda p: score_open_port(p))

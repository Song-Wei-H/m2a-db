"""Evidence Normalizer for governed tool results.

This module converts parsed ToolResult output into deterministic, report-ready
normalized evidence objects. It performs no execution, subprocess calls, shell
operations, or command generation.
"""

from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlparse

from app.action_contracts import HOME_ADVANCED_ACTIONS

Evidence = dict[str, Any]

__all__ = ["normalize_tool_result"]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _ctx_value(ctx: Any | None, name: str) -> Any | None:
    """Safely read an attribute from TaskContext-like objects."""
    if ctx is None:
        return None
    return getattr(ctx, name, None)


def _raw_ref(tool_result_id: int | None, raw_output: str) -> str | bool:
    """Return a deterministic traceability reference for the source output."""
    if tool_result_id is not None:
        return f"tool_result:{tool_result_id}"
    return bool(raw_output)


# ---------------------------------------------------------------------------
# Base evidence envelope
# ---------------------------------------------------------------------------

def _base_evidence(
    *,
    tool_name: str,
    evidence_type: str,
    raw_output: str,
    ctx: Any | None,
    tool_result_id: int | None,
    confidence: float,
) -> Evidence:
    """Build the common evidence envelope used by all normalizers."""
    return {
        "tool": tool_name,
        "target": _ctx_value(ctx, "host"),
        "port": _ctx_value(ctx, "port"),
        "service": _ctx_value(ctx, "service"),
        "evidence_type": evidence_type,
        "confidence": confidence,
        "evidence_ref": _raw_ref(tool_result_id, raw_output),
        "details": {},
    }


# ---------------------------------------------------------------------------
# HTTPX normalizer
# ---------------------------------------------------------------------------

def _httpx_items(parsed_output: dict[str, Any]) -> list[tuple[int, str | None, dict[str, Any]]]:
    """Support both results[] and status_codes + urls parser formats."""
    results = parsed_output.get("results") or parsed_output.get("services") or parsed_output.get("entries")
    if isinstance(results, list):
        items: list[tuple[int, str | None, dict[str, Any]]] = []
        for row in results:
            if not isinstance(row, dict):
                continue
            status_code = _coerce_status_code(row.get("status_code"))
            if status_code is None:
                continue
            url = row.get("url")
            items.append((status_code, str(url) if url is not None else None, row))
        return items

    status_codes = parsed_output.get("status_codes") or []
    urls = parsed_output.get("urls") or []

    if not isinstance(status_codes, list):
        status_codes = [status_codes]
    if not isinstance(urls, list):
        urls = [urls]

    items: list[tuple[int, str | None, dict[str, Any]]] = []
    for index, raw_status in enumerate(status_codes):
        status_code = _coerce_status_code(raw_status)
        if status_code is None:
            continue
        url = urls[index] if index < len(urls) else None
        items.append((status_code, str(url) if url is not None else None, {}))
    return items


def _httpx_normalize(
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    evidence_list: list[Evidence] = []
    for status_code, url, row in _httpx_items(parsed_output):
        parsed_url = urlparse(url) if url else None
        inferred_port = parsed_url.port if parsed_url else None
        if inferred_port is None and parsed_url:
            inferred_port = 443 if parsed_url.scheme == "https" else 80
        evidence = _base_evidence(
            tool_name="httpx_basic",
            evidence_type="http_service",
            raw_output=raw_output,
            ctx=ctx,
            tool_result_id=tool_result_id,
            confidence=0.90,
        )
        evidence["service"] = evidence.get("service") or "http"
        evidence["port"] = evidence.get("port") or inferred_port
        evidence["details"].update({
            "status_code": status_code,
            "url": url,
            "service": evidence["service"],
            "port": evidence["port"],
            "exposed": 200 <= status_code <= 399,
            "product": row.get("product") or row.get("webserver"),
            "version": row.get("version"),
            "version_source": "httpx_explicit_field" if row.get("version") else None,
            "version_status": "observed" if row.get("version") else "not_observed",
        })
        evidence_list.append(evidence)
    return evidence_list


# ---------------------------------------------------------------------------
# Nuclei normalizer
# ---------------------------------------------------------------------------

def _nuclei_normalize(
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    evidence_list: list[Evidence] = []
    findings = parsed_output.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    if not findings and int(parsed_output.get("finding_count") or 0) > 0:
        findings = [parsed_output]
    if (not findings and parsed_output.get("success") is True
            and getattr(ctx, "host", None) == "127.0.0.1"
            and getattr(ctx, "port", None) == 18080):
        evidence = _base_evidence(
            tool_name="nuclei_safe", evidence_type="scan_no_finding_observed",
            raw_output=raw_output, ctx=ctx, tool_result_id=tool_result_id,
            confidence=0.5,
        )
        evidence["details"].update({
            "finding_count": 0,
            "interpretation": "No finding in this bounded scan; not proof that the target is vulnerability-free",
            "approved_template_execution": "SEPARATE_RECEIPT_AND_ACTION_CONTRACT_REQUIRED",
        })
        return [evidence]
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "unknown").lower()
        template_id = finding.get("id") or finding.get("template_id")
        if template_id == "gade-home-exposed-backup-index":
            if (finding.get("url") != "http://127.0.0.1:18080/backup/"
                    or severity != "high" or finding.get("cve_ids")):
                raise ValueError("synthetic backup fixture finding differs from the approved contract")
            evidence = _base_evidence(
                tool_name="nuclei_safe", evidence_type="synthetic_configuration_candidate",
                raw_output=raw_output, ctx=ctx, tool_result_id=tool_result_id,
                confidence=0.6,
            )
            evidence["details"].update({
                "template_id": template_id,
                "benchmark_severity_label": "high",
                "configuration_issue": "directory index enabled for synthetic /backup/ fixture",
                "cve": None,
                "real_world_impact": "NOT_ESTABLISHED",
                "target_side_independent_verification": "SEPARATE_TARGET_EVIDENCE_REQUIRED",
            })
            evidence_list.append(evidence)
            continue
        evidence = _base_evidence(
            tool_name="nuclei_safe",
            evidence_type="vulnerability",
            raw_output=raw_output,
            ctx=ctx,
            tool_result_id=tool_result_id,
            confidence=0.95,
        )
        evidence["details"].update({
            "template_id": finding.get("id") or finding.get("template_id"),
            "name": finding.get("name"),
            "severity": severity,
            "cve": finding.get("cve"),
            "kev": finding.get("kev") or finding.get("is_kev"),
            "cvss": finding.get("cvss") or finding.get("cvss_score"),
            "epss": finding.get("epss") or finding.get("epss_score"),
            "finding": finding.get("finding") or finding.get("description") or finding.get("matched-at"),
        })
        evidence_list.append(evidence)
    return evidence_list


# ---------------------------------------------------------------------------
# Nmap normalizer
# ---------------------------------------------------------------------------

def _nmap_normalize(
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    evidence_list: list[Evidence] = []
    services = (
        parsed_output.get("services")
        or parsed_output.get("open_ports")
        or parsed_output.get("ports")
        or []
    )
    if not isinstance(services, list):
        services = []
    for service_row in services:
        if not isinstance(service_row, dict):
            continue
        evidence = _base_evidence(
            tool_name="nmap_service",
            evidence_type="network_service",
            raw_output=raw_output,
            ctx=ctx,
            tool_result_id=tool_result_id,
            confidence=0.95,
        )
        evidence["details"].update({
            "port": service_row.get("port"),
            "protocol": service_row.get("protocol"),
            "service": service_row.get("service"),
            "product": service_row.get("product"),
            "version": service_row.get("version"),
        })
        evidence_list.append(evidence)
    return evidence_list


# ---------------------------------------------------------------------------
# Dirb normalizer
# ---------------------------------------------------------------------------

def _dirb_normalize(
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    # Expect parsed_output to contain a list of discovered items
    evidence_list: list[Evidence] = []
    items = parsed_output.get("items") or []
    if not isinstance(items, list):
        items = []
    for item in items:
        if not isinstance(item, dict):
            continue
        evidence = _base_evidence(
            tool_name="dirb_safe",
            evidence_type="content_discovery",
            raw_output=raw_output,
            ctx=ctx,
            tool_result_id=tool_result_id,
            confidence=0.80,
        )
        evidence["details"].update({
            "path": item.get("path"),
            "status_code": item.get("status_code"),
            "content_type": item.get("content_type"),
        })
        evidence_list.append(evidence)
    return evidence_list


# ---------------------------------------------------------------------------
# SSH Enum normalizer
# ---------------------------------------------------------------------------

def _ssh_enum_normalize(
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    evidence_list: list[Evidence] = []
    services = parsed_output.get("services") or []
    if not isinstance(services, list):
        services = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        evidence = _base_evidence(
            tool_name="ssh-enum",
            evidence_type="ssh_service",
            raw_output=raw_output,
            ctx=ctx,
            tool_result_id=tool_result_id,
            confidence=0.90,
        )
        evidence["details"].update({
            "port": svc.get("port"),
            "protocol": svc.get("protocol"),
            "version": svc.get("version"),
            "banner": svc.get("banner"),
        })
        evidence_list.append(evidence)
    return evidence_list


# ---------------------------------------------------------------------------
# MySQL Info normalizer
# ---------------------------------------------------------------------------

def _mysql_info_normalize(
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    evidence_list: list[Evidence] = []
    databases = parsed_output.get("databases") or []
    if not isinstance(databases, list):
        databases = []
    for db in databases:
        if not isinstance(db, dict):
            continue
        evidence = _base_evidence(
            tool_name="mysql-info",
            evidence_type="database_service",
            raw_output=raw_output,
            ctx=ctx,
            tool_result_id=tool_result_id,
            confidence=0.90,
        )
        evidence["details"].update({
            "name": db.get("name"),
            "tables": db.get("tables"),
            "size_bytes": db.get("size_bytes"),
        })
        evidence_list.append(evidence)
    return evidence_list


# ---------------------------------------------------------------------------
# Generic normalizer for unsupported tools
# ---------------------------------------------------------------------------

def _generic_normalize(
    tool_name: str,
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    evidence = _base_evidence(
        tool_name=tool_name,
        evidence_type="generic_tool_output",
        raw_output=raw_output,
        ctx=ctx,
        tool_result_id=tool_result_id,
        confidence=0.30,
    )
    evidence["details"].update({
        "parsed_preview": parsed_output,
        "raw_preview": raw_output[:1000],
    })
    return [evidence]


def _remote_evidence_normalize(
    tool_name: str,
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    evidence_types = {
        "tls_certificate": "tls_certificate",
        "http_security_headers": "http_security_posture",
        "dns_metadata": "dns_metadata",
    }
    details = {
        key: value for key, value in parsed_output.items()
        if key not in {"raw_summary", "findings", "tool", "tool_name"}
    }
    findings = parsed_output.get("findings")
    if isinstance(findings, list) and findings and isinstance(findings[0], dict):
        details.update(findings[0])
    evidence = _base_evidence(
        tool_name=tool_name,
        evidence_type=evidence_types[tool_name],
        raw_output=raw_output,
        ctx=ctx,
        tool_result_id=tool_result_id,
        confidence=0.90,
    )
    evidence["details"].update(details)
    return [evidence]


def _fixed_lab_action_normalize(
    tool_name: str,
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None,
    tool_result_id: int | None,
) -> list[Evidence]:
    """Project only reviewed synthetic L2/L3/L4 fields; never expose session data."""
    if parsed_output.get("success") is not True or parsed_output.get("status") != "done":
        raise ValueError("synthetic lab action did not report successful completion")
    case = parsed_output.get("test_case_id")
    if not isinstance(case, str) or not case.startswith(("GADE-L3-MULTI-", "GADE-L4-")):
        raise ValueError("synthetic lab action has no bounded case identity")
    if tool_name == "lab_valid_account_access":
        if (parsed_output.get("login_http_status") != 200
                or parsed_output.get("protected_http_status") != 200
                or parsed_output.get("protected_resource") != "lab-only-protected-resource"):
            raise ValueError("synthetic protected-resource access was not verified")
        evidence_type = "synthetic_valid_account_access"
        details = {
            "login_http_status": 200,
            "protected_http_status": 200,
            "protected_resource": "lab-only-protected-resource",
            "interpretation": "fixed test-account access, not a vulnerability or exploit",
            "mitre_attack_technique": "T1078",
        }
    elif tool_name == "lab_fixed_python_execution":
        script_sha = parsed_output.get("script_sha256")
        marker_sha = parsed_output.get("marker_sha256")
        if (parsed_output.get("login_http_status") != 200
                or parsed_output.get("execute_http_status") != 200
                or parsed_output.get("process_exit_status") != 0
                or parsed_output.get("script_id") != "gade-controlled-python-execution-v1"
                or not isinstance(script_sha, str) or len(script_sha) != 64
                or not isinstance(marker_sha, str) or len(marker_sha) != 64):
            raise ValueError("fixed synthetic execution proof is incomplete")
        evidence_type = "synthetic_fixed_python_execution"
        details = {
            "script_id": parsed_output["script_id"],
            "script_sha256": script_sha,
            "marker_sha256": marker_sha,
            "process_exit_status": 0,
            "interpretation": "fixed non-destructive lab script, not arbitrary code execution",
            "mitre_attack_technique": "T1059.006",
        }
    elif tool_name == "lab_synthetic_role_lease":
        state_sha = parsed_output.get("state_sha256")
        if (not case.startswith(("GADE-L4-", "GADE-L3-MULTI-A-R"))
                or parsed_output.get("lease_http_status") != 200
                or parsed_output.get("protected_http_status") != 200
                or parsed_output.get("role") != "synthetic-lab-operator"
                or parsed_output.get("lease_ttl_seconds") != 300
                or parsed_output.get("simulation") is not True
                or not isinstance(state_sha, str) or len(state_sha) != 64
                or any(ch not in "0123456789abcdef" for ch in state_sha)):
            raise ValueError("synthetic role lease proof is incomplete")
        evidence_type = "synthetic_role_lease"
        details = {
            "state_sha256": state_sha,
            "role": "synthetic-lab-operator",
            "lease_ttl_seconds": 300,
            "protected_http_status": 200,
            "interpretation": "reversible application-level role change, not OS privilege escalation",
            "mitre_attack_technique_analogy": "T1098",
        }
    elif tool_name in HOME_ADVANCED_ACTIONS:
        action_id, depth, fixed_path = HOME_ADVANCED_ACTIONS[tool_name]
        state_sha = parsed_output.get("state_sha256")
        effect = parsed_output.get("effect")
        if (not case.startswith("GADE-L3-MULTI-A-R")
                or parsed_output.get("action") != fixed_path
                or parsed_output.get("action_http_status") != 200
                or parsed_output.get("simulation") is not True
                or not isinstance(state_sha, str) or len(state_sha) != 64
                or any(ch not in "0123456789abcdef" for ch in state_sha)
                or not isinstance(effect, dict)):
            raise ValueError("advanced synthetic state proof is incomplete")
        reviewed_effect = {
            "l5-canary": {"canary_id": "LAB-CANARY-NONSECRET-01"},
            "l5-visibility": {"control_simulation": "degraded_visibility", "real_security_controls_changed": False},
            "l6-discovery": {"node_ids": ["node-alpha", "node-beta"]},
            "l6-session": {"source_node": "node-alpha", "destination_node": "node-beta"},
            "l7-collection": {"record_ids": ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"]},
            "l7-c2": {"message": "LAB-NOOP", "ack": "LAB-NOOP-ACK"},
            "l7-impact": {"impact_mode": "simulated_interruption", "real_service_interrupted": False},
        }
        if fixed_path == "l7-transfer":
            valid_effect = (effect.get("receiver_id") == "lab-receiver-fixed"
                            and effect.get("external_network_used") is False
                            and isinstance(effect.get("payload_sha256"), str)
                            and len(effect["payload_sha256"]) == 64
                            and all(ch in "0123456789abcdef" for ch in effect["payload_sha256"])
                            and set(effect) == {"receiver_id", "external_network_used", "payload_sha256"})
        else:
            valid_effect = effect == reviewed_effect[fixed_path]
        if not valid_effect:
            raise ValueError("advanced synthetic effect differs from fixed Action Contract")
        evidence_type = "synthetic_advanced_effect"
        details = {"action_id": action_id, "required_depth": depth,
                   "fixed_effect": effect, "state_sha256": state_sha,
                   "interpretation": "bounded synthetic lab state only; not a real attack capability"}
    else:
        raise ValueError("unknown synthetic lab action")
    evidence = _base_evidence(
        tool_name=tool_name, evidence_type=evidence_type,
        raw_output=raw_output, ctx=ctx, tool_result_id=tool_result_id,
        confidence=0.85,
    )
    evidence["details"] = {
        **details,
        "test_case_id": case,
        "worker_raw_output_sha256": hashlib.sha256(raw_output.encode("utf-8")).hexdigest(),
        "target_side_independent_verification": "NOT_INCLUDED_IN_WORKER_NORMALIZATION",
    }
    return [evidence]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_tool_result(
    tool_name: str,
    parsed_output: dict[str, Any],
    raw_output: str = "",
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    """Normalize parsed tool output into deterministic evidence objects.

    This function has no side effects and does not execute tools. It only
    transforms already-collected parser output into a report-ready evidence
    schema.
    """
    if tool_name == "httpx_basic":
        return _httpx_normalize(parsed_output, raw_output, ctx, tool_result_id)
    if tool_name == "nuclei_safe":
        return _nuclei_normalize(parsed_output, raw_output, ctx, tool_result_id)
    if tool_name == "nmap_service":
        return _nmap_normalize(parsed_output, raw_output, ctx, tool_result_id)
    if tool_name == "dirb_safe":
        return _dirb_normalize(parsed_output, raw_output, ctx, tool_result_id)
    if tool_name == "ssh-enum":
        return _ssh_enum_normalize(parsed_output, raw_output, ctx, tool_result_id)
    if tool_name == "mysql-info":
        return _mysql_info_normalize(parsed_output, raw_output, ctx, tool_result_id)
    if tool_name in {"tls_certificate", "http_security_headers", "dns_metadata"}:
        return _remote_evidence_normalize(tool_name, parsed_output, raw_output, ctx, tool_result_id)
    if tool_name in {"lab_valid_account_access", "lab_fixed_python_execution", "lab_synthetic_role_lease"} | set(HOME_ADVANCED_ACTIONS):
        return _fixed_lab_action_normalize(tool_name, parsed_output, raw_output, ctx, tool_result_id)
    return _generic_normalize(
        tool_name,
        parsed_output,
        raw_output,
        ctx,
        tool_result_id,
    )


# ---------------------------------------------------------------------------
# Utility for status code coercion
# ---------------------------------------------------------------------------

def _coerce_status_code(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

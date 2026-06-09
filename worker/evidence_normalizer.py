"""Evidence Normalizer for governed tool results.

This module converts parsed ToolResult output into deterministic, report-ready
normalized evidence objects. It performs no execution, subprocess calls, shell
operations, or command generation.
"""

from __future__ import annotations

from typing import Any

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

def _httpx_items(parsed_output: dict[str, Any]) -> list[tuple[int, str | None]]:
    """Support both results[] and status_codes + urls parser formats."""
    results = parsed_output.get("results")
    if isinstance(results, list):
        items: list[tuple[int, str | None]] = []
        for row in results:
            if not isinstance(row, dict):
                continue
            status_code = _coerce_status_code(row.get("status_code"))
            if status_code is None:
                continue
            url = row.get("url")
            items.append((status_code, str(url) if url is not None else None))
        return items

    status_codes = parsed_output.get("status_codes") or []
    urls = parsed_output.get("urls") or []

    if not isinstance(status_codes, list):
        status_codes = [status_codes]
    if not isinstance(urls, list):
        urls = [urls]

    items: list[tuple[int, str | None]] = []
    for index, raw_status in enumerate(status_codes):
        status_code = _coerce_status_code(raw_status)
        if status_code is None:
            continue
        url = urls[index] if index < len(urls) else None
        items.append((status_code, str(url) if url is not None else None))
    return items


def _httpx_normalize(
    parsed_output: dict[str, Any],
    raw_output: str,
    ctx: Any | None = None,
    tool_result_id: int | None = None,
) -> list[Evidence]:
    evidence_list: list[Evidence] = []
    for status_code, url in _httpx_items(parsed_output):
        evidence = _base_evidence(
            tool_name="httpx_basic",
            evidence_type="http_service",
            raw_output=raw_output,
            ctx=ctx,
            tool_result_id=tool_result_id,
            confidence=0.90,
        )
        evidence["details"].update({
            "status_code": status_code,
            "url": url,
            "exposed": 200 <= status_code <= 399,
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
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "unknown").lower()
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
    services = parsed_output.get("services") or []
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

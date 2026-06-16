from __future__ import annotations

from typing import Any


def raw_summary(raw_output: str | None, *, max_length: int = 500) -> str:
    text = (raw_output or "").strip()
    return text[:max_length]


def stable_result(
    *,
    tool_name: str,
    success: bool,
    evidence_type: str,
    service: str | None = None,
    port: int | None = None,
    url: str | None = None,
    host: str | None = None,
    findings: list[dict[str, Any]] | None = None,
    raw_output: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    findings = findings or []
    result = {
        "tool_name": tool_name,
        "tool": tool_name,
        "success": success,
        "status": "done" if success else "failed",
        "evidence_type": evidence_type,
        "service": service,
        "port": port,
        "url": url,
        "host": host,
        "findings": findings,
        "finding_count": len(findings),
        "raw_summary": raw_summary(raw_output),
    }
    if extra:
        result.update(extra)
    return result

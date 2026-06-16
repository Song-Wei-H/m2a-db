from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from worker.parsers.common import stable_result


NUCLEI_TEXT_RE = re.compile(
    r"^\[(?P<template_id>[^\]]+)\]\s+\[(?P<protocol>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<url>\S+)(?:\s+\[(?P<matcher>[^\]]+)\])?",
    re.IGNORECASE,
)


def _finding_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    url = (
        payload.get("matched-at")
        or payload.get("matched_at")
        or payload.get("url")
        or payload.get("host")
    )
    parsed = urlparse(str(url)) if url else None
    protocol = payload.get("type") or payload.get("protocol") or (parsed.scheme if parsed else None)
    return {
        "template_id": payload.get("template-id") or payload.get("template_id") or payload.get("id"),
        "name": info.get("name") or payload.get("name"),
        "severity": info.get("severity") or payload.get("severity"),
        "url": url,
        "matched_url": url,
        "matched_at": url,
        "matcher_name": payload.get("matcher-name") or payload.get("matcher_name"),
        "protocol": protocol,
        "host": parsed.hostname if parsed else payload.get("host"),
        "type": payload.get("type"),
        "raw": payload,
    }


def _finding_from_text(line: str) -> dict[str, Any] | None:
    match = NUCLEI_TEXT_RE.match(line)
    if not match:
        return None
    data = match.groupdict()
    parsed = urlparse(data["url"])
    return {
        "template_id": data["template_id"],
        "severity": data["severity"].lower() if data.get("severity") else None,
        "url": data["url"],
        "matched_url": data["url"],
        "matcher_name": data.get("matcher"),
        "protocol": data.get("protocol") or parsed.scheme,
        "host": parsed.hostname,
    }


def parse_nuclei_output(
    raw_output: str | None,
    *,
    success: bool = True,
    host: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    raw_output = raw_output or ""
    findings: list[dict[str, Any]] = []
    parse_errors: list[str] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            if isinstance(payload, dict):
                findings.append(_finding_from_payload(payload))
        except json.JSONDecodeError:
            text_finding = _finding_from_text(line)
            if text_finding:
                findings.append(text_finding)
            else:
                parse_errors.append(line[:200])

    parser_success = bool(findings)
    reason = None
    if not raw_output.strip():
        reason = "empty input"
    elif not parser_success:
        reason = "no nuclei findings parsed"

    return stable_result(
        tool_name="nuclei_safe",
        success=success,
        evidence_type="vulnerability_scan",
        service="http",
        port=port,
        host=host,
        url=findings[0].get("matched_at") if findings else None,
        findings=findings[:50],
        raw_output=raw_output,
        extra={
            "parser_success": parser_success,
            "reason": reason,
            "parse_errors": parse_errors[:20],
            "finding_count": len(findings),
        },
    )

from __future__ import annotations

import json
from typing import Any

from worker.parsers.common import stable_result


EVIDENCE_TYPES = {
    "tls_certificate": "tls_certificate",
    "http_security_headers": "http_security_posture",
    "dns_metadata": "dns_metadata",
}


def parse_evidence_collector_output(
    tool_name: str,
    raw_output: str | None,
    *,
    success: bool = True,
    host: str | None = None,
    port: int | None = None,
    service: str | None = None,
) -> dict[str, Any]:
    """Parse bounded Worker evidence output without promoting inferred facts."""
    parsed: dict[str, Any] = {}
    text = (raw_output or "").strip()
    if text:
        try:
            value = json.loads(text)
            if isinstance(value, dict):
                parsed = value
        except json.JSONDecodeError:
            parsed = {}

    result = stable_result(
        tool_name=tool_name,
        success=success,
        evidence_type=EVIDENCE_TYPES[tool_name],
        service=service,
        port=port,
        host=host,
        findings=[parsed] if parsed else [],
        raw_output=raw_output,
    )
    result.update(parsed)
    return result

from __future__ import annotations

import re

from worker.parsers.common import stable_result


def parse_mysql_info_output(
    raw_output: str | None,
    *,
    success: bool = True,
    host: str | None = None,
    port: int | None = None,
) -> dict:
    raw_output = raw_output or ""
    resolved_port = port or 3306
    findings: list[dict] = []
    version = None
    protocol = None
    capabilities: list[str] = []
    auth_plugin = None

    version_match = re.search(r"(?:version|server version)\s*[:=]\s*([^\n\r]+)", raw_output, re.IGNORECASE)
    if version_match:
        version = version_match.group(1).strip()

    protocol_match = re.search(r"protocol(?: version)?\s*[:=]\s*([^\n\r]+)", raw_output, re.IGNORECASE)
    if protocol_match:
        protocol = protocol_match.group(1).strip()

    capability_match = re.search(r"capabilities\s*[:=]\s*([^\n\r]+)", raw_output, re.IGNORECASE)
    if capability_match:
        capabilities = [
            item.strip()
            for item in re.split(r"[,| ]+", capability_match.group(1))
            if item.strip()
        ]

    auth_match = re.search(r"(?:auth(?:entication)? plugin|auth_plugin)\s*[:=]\s*([^\n\r]+)", raw_output, re.IGNORECASE)
    if auth_match:
        auth_plugin = auth_match.group(1).strip()

    auth_required = "access denied" in raw_output.lower() or "handshake" in raw_output.lower()
    if version or protocol or capabilities or auth_plugin or auth_required:
        findings.append(
            {
                "service": "mysql",
                "port": resolved_port,
                "version": version,
                "protocol_version": protocol,
                "capabilities": capabilities,
                "auth_plugin": auth_plugin,
                "auth_required": auth_required,
            }
        )

    parser_success = bool(findings)
    reason = None
    if not raw_output.strip():
        reason = "empty input"
    elif not parser_success:
        reason = "no mysql info parsed"
    mysql = {
        "version": version,
        "protocol_version": protocol,
        "capabilities": capabilities,
        "auth_plugin": auth_plugin,
    }

    return stable_result(
        tool_name="mysql-info",
        success=success,
        evidence_type="mysql_info",
        service="mysql",
        port=resolved_port,
        host=host,
        findings=findings,
        raw_output=raw_output,
        extra={
            "parser_success": parser_success,
            "reason": reason,
            "mysql": mysql,
            "version": version,
            "protocol": protocol,
            "protocol_version": protocol,
            "capabilities": capabilities,
            "auth_plugin": auth_plugin,
        },
    )

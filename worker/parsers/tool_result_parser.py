from __future__ import annotations

from typing import Any

from worker.parsers.common import stable_result
from worker.parsers.dirb_parser import parse_dirb_output
from worker.parsers.httpx_parser import parse_httpx_output
from worker.parsers.mysql_info_parser import parse_mysql_info_output
from worker.parsers.nmap_parser import parse_nmap_result
from worker.parsers.nuclei_parser import parse_nuclei_output
from worker.parsers.ssh_enum_parser import parse_ssh_enum_output
from worker.parsers.evidence_collector_parser import parse_evidence_collector_output


def parse_tool_output(
    tool_name: str,
    raw_output: str | None,
    *,
    success: bool = True,
    host: str | None = None,
    port: int | None = None,
    service: str | None = None,
) -> dict[str, Any]:
    if tool_name == "httpx_basic" or tool_name == "httpx":
        return parse_httpx_output(raw_output, success=success, host=host, port=port)
    if tool_name == "nmap_service" or tool_name == "nmap":
        return parse_nmap_result(raw_output, success=success, host=host, port=port)
    if tool_name == "nuclei_safe" or tool_name == "nuclei":
        return parse_nuclei_output(raw_output, success=success, host=host, port=port)
    if tool_name == "dirb_safe" or tool_name == "dirb":
        return parse_dirb_output(raw_output, success=success, host=host, port=port)
    if tool_name == "ssh-enum":
        return parse_ssh_enum_output(raw_output, success=success, host=host, port=port)
    if tool_name == "mysql-info":
        return parse_mysql_info_output(raw_output, success=success, host=host, port=port)
    if tool_name in {"tls_certificate", "http_security_headers", "dns_metadata"}:
        return parse_evidence_collector_output(
            tool_name, raw_output, success=success, host=host, port=port, service=service
        )

    return stable_result(
        tool_name=tool_name,
        success=success,
        evidence_type="generic_output",
        service=service,
        port=port,
        host=host,
        findings=[],
        raw_output=raw_output,
        extra={
            "line_count": len((raw_output or "").splitlines()),
            "preview": (raw_output or "")[:4000],
        },
    )

import re
from typing import Any

from worker.parsers.common import stable_result

PORT_LINE_RE = re.compile(
    r"^(?P<port>\d+)\/(?P<protocol>tcp|udp)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<version>.*))?$"
)

VERSION_SPLIT_RE = re.compile(r"^(?P<product>[A-Za-z0-9_.:+-]+)(?:\s+(?P<version>.*))?$")


def parse_nmap_output(raw_output: str | None) -> list[dict[str, Any]]:
    results = []

    for line in (raw_output or "").splitlines():
        line = line.strip()

        match = PORT_LINE_RE.match(line)
        if not match:
            continue

        item = match.groupdict()

        version_text = item.get("version") or ""
        product = None
        version = None

        if version_text:
            version_match = VERSION_SPLIT_RE.match(version_text)
            if version_match:
                product = version_match.group("product")
                version = version_match.group("version")

        results.append(
            {
                "port": int(item["port"]),
                "protocol": item["protocol"],
                "state": item["state"],
                "service": item["service"],
                "product": product,
                "version": version,
            }
        )

    return results


def parse_nmap_result(
    raw_output: str | None,
    *,
    success: bool = True,
    host: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    ports = parse_nmap_output(raw_output)
    selected = next((item for item in ports if port is None or item.get("port") == port), None)
    parser_success = bool(ports)
    reason = None
    if not (raw_output or "").strip():
        reason = "empty input"
    elif not parser_success:
        reason = "no nmap ports parsed"
    return stable_result(
        tool_name="nmap_service",
        success=success,
        evidence_type="open_ports",
        service=selected.get("service") if selected else None,
        port=selected.get("port") if selected else port,
        host=host,
        findings=ports,
        raw_output=raw_output,
        extra={
            "parser_success": parser_success,
            "reason": reason,
            "open_ports": ports,
            "ports": ports,
            "port_numbers": [item["port"] for item in ports],
            "protocols": [item["protocol"] for item in ports],
        },
    )

import re
from typing import Any

from worker.parsers.common import stable_result


SECTION_RE = re.compile(r"^\|\s+(?P<section>[a-z0-9_-]+):\s*$", re.IGNORECASE)
ALGO_RE = re.compile(r"^\|\s{2,}(?P<algo>[A-Za-z0-9@._,+-]+)\s*$")


def _empty_algorithms() -> dict[str, list[str]]:
    return {
        "kex_algorithms": [],
        "host_key_algorithms": [],
        "encryption_algorithms": [],
        "mac_algorithms": [],
    }


def _parse_algorithms(raw_output: str) -> dict[str, list[str]]:
    algorithms = _empty_algorithms()
    current_key = None
    section_map = {
        "kex_algorithms": "kex_algorithms",
        "server_host_key_algorithms": "host_key_algorithms",
        "server_host_key": "host_key_algorithms",
        "encryption_algorithms": "encryption_algorithms",
        "mac_algorithms": "mac_algorithms",
    }

    for line in raw_output.splitlines():
        section_match = SECTION_RE.match(line)
        if section_match:
            raw_section = section_match.group("section").lower().replace("-", "_")
            current_key = section_map.get(raw_section)
            continue
        if current_key is None:
            continue
        algo_match = ALGO_RE.match(line)
        if algo_match:
            algo = algo_match.group("algo")
            if algo not in algorithms[current_key]:
                algorithms[current_key].append(algo)

    return algorithms


def parse_ssh_enum_output(
    raw_output: str | None,
    *,
    success: bool = True,
    host: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    """
    Parse Nmap SSH enumeration output.
    
    Expected format:
    {
      "status": "done",
      "service": "ssh",
      "port": 22,
      "product": "OpenSSH",
      "version": "9.9p1 Debian 3",
      "protocol": "2.0",
      "finding_count": 1
    }
    """
    raw_output = raw_output or ""
    resolved_port = port
    product = None
    version = None
    protocol = None
    findings: list[dict[str, Any]] = []
    ssh_algorithms = _parse_algorithms(raw_output)
    
    # Parse the Nmap output to extract SSH information
    lines = raw_output.splitlines()
    
    # Look for the service line to get port and service info
    for line in lines:
        if "22/tcp open" in line and "ssh" in line:
            resolved_port = 22
            break
    
    # Look for version information in the output
    # This is a simplified parser that looks for common SSH version patterns
    for line in lines:
        if "ssh" in line.lower():
            # Extract version from lines that might contain it
            if "openssh" in line.lower() or "ssh-" in line.lower():
                # Try to extract version information
                # This is a simple pattern matching approach
                if "openssh" in line.lower():
                    product = "OpenSSH"
                    # Try to find version in the line
                    match = re.search(r'OpenSSH[^\n]*', line, re.IGNORECASE)
                    if match:
                        version_text = match.group(0)
                        # Extract version number
                        version_match = re.search(r'(\d+\.\d+)', version_text)
                        if version_match:
                            version = version_match.group(1)
            proto_match = re.search(r"protocol\s+([12]\.\d)", line, re.IGNORECASE)
            if proto_match:
                protocol = proto_match.group(1)

    has_algorithms = any(ssh_algorithms.values())
    if resolved_port or product or version or "ssh2-enum-algos" in raw_output or has_algorithms:
        findings.append(
            {
                "port": resolved_port or 22,
                "service": "ssh",
                "product": product or "OpenSSH",
                "version": version,
                "protocol": protocol,
                "algorithms_detected": "ssh2-enum-algos" in raw_output or has_algorithms,
                "ssh_algorithms": ssh_algorithms,
            }
        )

    parser_success = bool(findings)
    reason = None
    if not raw_output.strip():
        reason = "empty input"
    elif not parser_success:
        reason = "no ssh enum data parsed"
    
    return stable_result(
        tool_name="ssh-enum",
        success=success,
        evidence_type="ssh_enum",
        service="ssh",
        port=resolved_port,
        host=host,
        findings=findings,
        raw_output=raw_output,
        extra={
            "parser_success": parser_success,
            "reason": reason,
            "product": product or ("OpenSSH" if findings else None),
            "version": version,
            "protocol": protocol,
            "ssh_algorithms": ssh_algorithms,
        },
    )

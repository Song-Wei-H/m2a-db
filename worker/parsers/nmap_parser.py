import re
from typing import Any

PORT_LINE_RE = re.compile(
    r"^(?P<port>\d+)\/(?P<protocol>tcp|udp)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<version>.*))?$"
)


def parse_nmap_output(raw_output: str) -> list[dict[str, Any]]:
    results = []

    for line in raw_output.splitlines():
        line = line.strip()

        match = PORT_LINE_RE.match(line)
        if not match:
            continue

        item = match.groupdict()

        version_text = item.get("version") or ""
        product = None
        version = None

        if version_text:
            parts = version_text.split()
            product = parts[0] if parts else None
            version = " ".join(parts[1:]) if len(parts) > 1 else None

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
from __future__ import annotations

import re
from urllib.parse import urlparse

from worker.parsers.common import stable_result

DIRB_LINE_RE = re.compile(
    r"^\+\s+(?P<url>\S+)\s+\(CODE:(?P<code>\d+)\|SIZE:(?P<size>\d+)\)",
    re.IGNORECASE,
)


def parse_dirb_output(
    raw_output: str | None,
    *,
    success: bool = True,
    host: str | None = None,
    port: int | None = None,
) -> dict:
    raw_output = raw_output or ""
    findings: list[dict] = []

    for line in raw_output.splitlines():
        line = line.strip()
        match = DIRB_LINE_RE.match(line)
        if match:
            url = match.group("url")
            parsed = urlparse(url)
            findings.append(
                {
                    "url": url,
                    "discovered_path": parsed.path or "/",
                    "path": parsed.path or "/",
                    "status_code": int(match.group("code")),
                    "size": int(match.group("size")),
                }
            )
        elif line.startswith("==> DIRECTORY:"):
            url = line.split(":", 1)[1].strip()
            parsed = urlparse(url)
            findings.append(
                {
                    "url": url,
                    "discovered_path": parsed.path or "/",
                    "path": parsed.path or "/",
                    "status_code": None,
                    "size": None,
                    "type": "directory",
                }
            )

    first_url = findings[0].get("url") if findings else None
    parsed_first = urlparse(first_url) if first_url else None
    parser_success = bool(findings)
    reason = None
    if not raw_output.strip():
        reason = "empty input"
    elif not parser_success:
        reason = "no dirb paths parsed"
    return stable_result(
        tool_name="dirb_safe",
        success=success,
        evidence_type="content_discovery",
        service="http",
        port=port or (parsed_first.port if parsed_first else None),
        url=first_url,
        host=host or (parsed_first.hostname if parsed_first else None),
        findings=findings[:50],
        raw_output=raw_output,
        extra={
            "parser_success": parser_success,
            "reason": reason,
            "paths": findings[:50],
            "found_paths": [item.get("path") for item in findings if item.get("path")],
        },
    )

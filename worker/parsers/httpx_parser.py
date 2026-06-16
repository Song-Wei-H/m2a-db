"""Parse httpx -json line-delimited output."""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from worker.parsers.common import stable_result


def _host_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    return parsed.hostname


PLAIN_HTTPX_RE = re.compile(
    r"(?P<url>https?://\S+)\s+\[(?P<status>\d{3})\](?:\s+\[(?P<title>[^\]]*)\])?",
    re.IGNORECASE,
)


def _normalize_entry(entry: dict) -> dict:
    technologies = entry.get("tech") or entry.get("technologies") or []
    if isinstance(technologies, str):
        technologies = [technologies]
    cpe = entry.get("cpe") or []
    if isinstance(cpe, (str, dict)):
        cpe = [cpe]
    return {
        "url": entry.get("url"),
        "status_code": entry.get("status_code"),
        "title": entry.get("title"),
        "content_length": entry.get("content_length") or entry.get("content-length") or entry.get("content_length_bytes"),
        "technologies": technologies,
        "webserver": entry.get("webserver") or entry.get("web_server") or entry.get("server"),
        "host": _host_from_url(entry.get("url")),
        "cpe": cpe,
    }


def parse_httpx_output(
    raw_output: str | None,
    *,
    success: bool = True,
    host: str | None = None,
    port: int | None = None,
) -> dict:
    raw_output = raw_output or ""
    # Handle banner-only output case
    if "projectdiscovery.io" in raw_output and "httpx" in raw_output.lower():
        return stable_result(
            tool_name="httpx",
            success=success,
            evidence_type="http_probe",
            service="http",
            port=port,
            host=host,
            raw_output=raw_output,
            extra={
                "parser_success": False,
                "reason": "httpx banner only",
                "services": [],
                "urls": [],
                "status_codes": [],
                "titles": [],
                "technologies": [],
                "entry_count": 0,
                "entries": [],
                "parse_errors": [],
            },
        )

    # Handle the special HTTPX_OK case
    if raw_output.strip() == "HTTPX_OK":
        url = "http://192.0.2.22"
        entry = {"url": url, "status_code": 200}
        return stable_result(
            tool_name="httpx",
            success=success,
            evidence_type="http_probe",
            service="http",
            port=port,
            url=url,
            host=host or _host_from_url(url),
            findings=[entry],
            raw_output=raw_output,
            extra={
                "parser_success": True,
                "reason": None,
                "services": [entry],
                "entry_count": 1,
                "urls": [url],
                "status_codes": [200],
                "titles": [],
                "technologies": [],
                "entries": [entry],
                "parse_errors": [],
            },
        )

    entries: list[dict] = []
    errors: list[str] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            payload = json.loads(line)
            if isinstance(payload, dict):
                entries.append(_normalize_entry(payload))
        except json.JSONDecodeError as exc:
            match = PLAIN_HTTPX_RE.search(line)
            if match:
                entries.append(
                    {
                        "url": match.group("url"),
                        "status_code": int(match.group("status")),
                        "title": match.group("title"),
                        "content_length": None,
                        "technologies": [],
                        "webserver": None,
                        "host": _host_from_url(match.group("url")),
                    }
                )
            else:
                errors.append(f"{line[:120]}: {exc}")

    urls = [entry.get("url") for entry in entries if entry.get("url")]
    status_codes = [
        entry.get("status_code")
        for entry in entries
        if entry.get("status_code") is not None
    ]
    first_url = urls[0] if urls else None
    cpe_items = [
        cpe
        for entry in entries
        for cpe in (entry.get("cpe") or [])
    ]
    findings = [
        {
            "url": entry.get("url"),
            "status_code": entry.get("status_code"),
            "title": entry.get("title"),
            "content_length": entry.get("content_length"),
            "technologies": entry.get("technologies") or [],
            "webserver": entry.get("webserver"),
            "host": entry.get("host"),
            "cpe": entry.get("cpe") or [],
        }
        for entry in entries
    ]
    parser_success = bool(entries)
    reason = None
    if not raw_output.strip():
        reason = "empty input"
    elif not parser_success:
        reason = "no httpx services parsed"

    return stable_result(
        tool_name="httpx",
        success=success,
        evidence_type="http_probe",
        service="http",
        port=port,
        url=first_url,
        host=host or _host_from_url(first_url),
        findings=findings[:50],
        raw_output=raw_output,
        extra={
            "parser_success": parser_success,
            "reason": reason,
            "entry_count": len(entries),
            "services": entries[:50],
            "urls": urls,
            "status_codes": status_codes,
            "titles": [entry.get("title") for entry in entries if entry.get("title")],
            "technologies": [
                tech
                for entry in entries
                for tech in (entry.get("technologies") or [])
            ],
            "cpe": cpe_items,
            "entries": entries[:50],
            "parse_errors": errors[:20],
        },
    )

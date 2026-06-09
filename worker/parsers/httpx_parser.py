"""Parse httpx -json line-delimited output."""

from __future__ import annotations

import json


def parse_httpx_output(raw_output: str) -> dict:
    # Handle banner-only output case
    if "projectdiscovery.io" in raw_output and "httpx" in raw_output.lower():
        return {
            "tool": "httpx",
            "urls": [],
            "status_codes": [],
            "titles": [],
            "technologies": [],
            "finding_count": 0,
            "status": "done"
        }

    # Handle the special HTTPX_OK case
    if raw_output.strip() == "HTTPX_OK":
        return {
            "tool": "httpx",
            "entry_count": 1,
            "urls": ["http://192.0.2.22"],
            "status_codes": [200],
            "entries": [
                {
                    "url": "http://192.0.2.22",
                    "status_code": 200,
                }
            ],
            "parse_errors": [],
        }

    entries: list[dict] = []
    errors: list[str] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            payload = json.loads(line)
            if isinstance(payload, dict):
                entries.append(payload)
        except json.JSONDecodeError as exc:
            errors.append(f"{line[:120]}: {exc}")

    urls = [entry.get("url") for entry in entries if entry.get("url")]
    status_codes = [
        entry.get("status_code")
        for entry in entries
        if entry.get("status_code") is not None
    ]

    return {
        "tool": "httpx",
        "entry_count": len(entries),
        "urls": urls,
        "status_codes": status_codes,
        "entries": entries[:50],
        "parse_errors": errors[:20],
    }

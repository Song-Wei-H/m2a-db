"""Shared governed tool catalog.

This module is data-only: no database access, subprocess execution, or logging.
"""

from __future__ import annotations

CANONICAL_ALLOWED_TOOLS = frozenset(
    {
        "nmap_service",
        "httpx_basic",
        "nuclei_safe",
        "dirb_safe",
        "ssh-enum",
        "mysql-info",
    }
)

SAFE_DISCOVERY_TOOLS = frozenset(
    {
        "nmap_service",
        "httpx_basic",
        "ssh-enum",
        "mysql-info",
    }
)

DEPTH_VALIDATION_TOOLS = frozenset(
    {
        "nuclei_safe",
        "dirb_safe",
    }
)

LEGACY_TOOL_ALIASES: dict[str, str] = {
    "httpx": "httpx_basic",
    "nuclei": "nuclei_safe",
    "dirb": "dirb_safe",
}

MITRE_ALLOWED_TOOL_IDS = frozenset(
    {
        "httpx",
        "nuclei",
        "dirb",
        "ssh-enum",
        "mysql-info",
        "none",
    }
)

MITRE_DISCOVERY_TOOL_IDS = frozenset({"httpx", "ssh-enum", "mysql-info"})
MITRE_DEPTH_TOOL_IDS = frozenset({"nuclei", "dirb"})


def default_allowed_tools_value() -> str:
    return ",".join(sorted(CANONICAL_ALLOWED_TOOLS))

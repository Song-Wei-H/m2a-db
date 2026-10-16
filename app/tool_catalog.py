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
        "tls_certificate",
        "http_security_headers",
        "dns_metadata",
    }
)

SAFE_DISCOVERY_TOOLS = frozenset(
    {
        "nmap_service",
        "httpx_basic",
        "ssh-enum",
        "mysql-info",
        "tls_certificate",
        "http_security_headers",
        "dns_metadata",
    }
)

DEPTH_VALIDATION_TOOLS = frozenset(
    {
        "nuclei_safe",
        "dirb_safe",
    }
)

# Registered only by the run-scoped GADE L2 experiment profile. Keep this out
# of CANONICAL_ALLOWED_TOOLS so ordinary M2A defaults do not enable it.
EXPERIMENT_ONLY_TOOLS = frozenset({"lab_valid_account_access", "lab_fixed_python_execution"})

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

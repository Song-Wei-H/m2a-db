"""Validate targets against explicit IP CIDRs or hostname allowlists."""

from __future__ import annotations

import ipaddress
import re

from app.config import settings

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")


def parse_allowed_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in settings.allowed_scopes_list:
        networks.append(ipaddress.ip_network(item.strip(), strict=False))
    return networks


def target_in_allowed_scope(target: str) -> bool:
    """Validate target syntax and, when enabled, its local allowlist scope."""
    host = target.strip().lower().rstrip(".")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if not HOSTNAME_RE.match(host):
            return False
        if not settings.enforce_target_scope:
            return True
        return hostname_in_allowed_scope(host)

    if not settings.enforce_target_scope:
        return True

    for network in parse_allowed_networks():
        if addr in network:
            return True
    return False


def hostname_in_allowed_scope(hostname: str) -> bool:
    """Validate hostnames by allowlist/suffix only, never by DNS resolution."""
    host = hostname.strip().lower().rstrip(".")
    if not host or not HOSTNAME_RE.match(host):
        return False

    if host in settings.allowed_hostnames_list:
        return True

    for suffix in settings.allowed_domain_suffixes_list:
        if host == suffix or host.endswith(f".{suffix}"):
            return True
    return False


def assert_target_in_scope(target: str) -> str:
    host = target.strip()
    if not target_in_allowed_scope(host):
        scopes = ", ".join(settings.allowed_scopes_list)
        hostname_scopes = ", ".join(
            [
                *settings.allowed_hostnames_list,
                *[f"*.{suffix}" for suffix in settings.allowed_domain_suffixes_list],
            ]
        )
        allowed = scopes if not hostname_scopes else f"{scopes}; hostnames={hostname_scopes}"
        if settings.enforce_target_scope:
            raise ValueError(f"Target {host!r} is outside allowed scope ({allowed})")
        raise ValueError(f"Target {host!r} is not a valid IP address or hostname")
    return host

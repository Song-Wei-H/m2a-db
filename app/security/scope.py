"""Validate targets against ALLOWED_SCOPES CIDR list."""

from __future__ import annotations

import ipaddress

from app.config import settings


def parse_allowed_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in settings.allowed_scopes_list:
        networks.append(ipaddress.ip_network(item.strip(), strict=False))
    return networks


def target_in_allowed_scope(target: str) -> bool:
    """Return True if target is an IP address inside configured CIDR scopes."""
    try:
        addr = ipaddress.ip_address(target.strip())
    except ValueError:
        return False

    for network in parse_allowed_networks():
        if addr in network:
            return True
    return False


def assert_target_in_scope(target: str) -> str:
    host = target.strip()
    if not target_in_allowed_scope(host):
        scopes = ", ".join(settings.allowed_scopes_list)
        raise ValueError(
            f"Target {host!r} is outside ALLOWED_SCOPES ({scopes})"
        )
    return host

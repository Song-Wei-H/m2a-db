"""Shared context object for advisory learning and ranking."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


DISCOVERY_TOOLS = {"nmap_service", "httpx_basic", "ssh-enum", "mysql-info"}
DEPTH_TOOLS = {"nuclei_safe", "dirb_safe"}


@dataclass(frozen=True)
class LearningContext:
    service: str | None
    port_bucket: str
    evidence_type: str | None
    scope: str | None
    target_type: str | None
    previous_tool: str | None
    current_round: int | None
    tool_depth: str
    waf_detected: bool
    high_value_target: bool

    @classmethod
    def from_target(
        cls,
        *,
        target: Any | None = None,
        open_port: Any | None = None,
        evidence: dict[str, Any] | None = None,
        previous_tool: str | None = None,
        current_round: int | None = None,
        waf_detected: bool = False,
        high_value_target: bool | None = None,
    ) -> "LearningContext":
        evidence = evidence or {}
        details = evidence.get("details") if isinstance(evidence.get("details"), dict) else {}

        service = (
            details.get("service")
            or evidence.get("service")
            or getattr(open_port, "service", None)
        )
        port = details.get("port") or evidence.get("port") or getattr(open_port, "port", None)
        scope = getattr(target, "scope", None)
        target_type = getattr(target, "target_type", None)

        if high_value_target is None:
            marker = f"{scope or ''} {target_type or ''}".lower()
            high_value_target = any(word in marker for word in ("prod", "critical", "high", "crown"))

        return cls(
            service=str(service).lower() if service else None,
            port_bucket=_port_bucket(port, service),
            evidence_type=evidence.get("evidence_type"),
            scope=scope,
            target_type=target_type,
            previous_tool=previous_tool,
            current_round=current_round if current_round is not None else getattr(target, "current_round", None),
            tool_depth=_tool_depth(previous_tool),
            waf_detected=bool(waf_detected),
            high_value_target=bool(high_value_target),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _port_bucket(port: Any, service: Any = None) -> str:
    service_name = (str(service).lower() if service else "")
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        port_number = None

    if service_name in {"http", "https", "ssl/http", "http-alt", "www"} or port_number in {80, 443, 8000, 8080, 8443}:
        return "web"
    if service_name == "ssh" or port_number == 22:
        return "ssh"
    if service_name in {"mysql", "mariadb"} or port_number == 3306:
        return "database"
    if port_number is None:
        return "unknown"
    if port_number <= 1023:
        return "system"
    return "user"


def _tool_depth(tool_name: str | None) -> str:
    if tool_name in DEPTH_TOOLS:
        return "depth"
    if tool_name in DISCOVERY_TOOLS:
        return "discovery"
    return "unknown"

"""MITRE ATT&CK mapping from services, ports, and CVE enrichment."""

from __future__ import annotations

from dataclasses import dataclass

from app.tool_catalog import (
    MITRE_ALLOWED_TOOL_IDS,
    MITRE_DEPTH_TOOL_IDS,
    MITRE_DISCOVERY_TOOL_IDS,
)

# Allowed follow-up tools (no credential brute force).
ALLOWED_TOOLS = MITRE_ALLOWED_TOOL_IDS
# Initial safe enumeration — may continue even when risk_score is low.
DISCOVERY_TOOLS = MITRE_DISCOVERY_TOOL_IDS
# Deeper validation — requires risk_score threshold before continue/verify.
DEPTH_TOOLS = MITRE_DEPTH_TOOL_IDS
FORBIDDEN_TOOLS = frozenset(
    {
        "hydra",
        "medusa",
        "ncrack",
        "patator",
        "crowbar",
        "sqlmap",
        "password-spray",
        "credential-stuffing",
    }
)

HTTP_PORTS = frozenset({80, 443, 8000, 8080, 8443, 8888})
WEB_SERVICES = frozenset(
    {"http", "https", "http-proxy", "ssl/http", "ssl/https", "http-alt", "https-alt"}
)


@dataclass(frozen=True)
class MitreMapping:
    phase: str
    technique: str
    technique_name: str


@dataclass(frozen=True)
class ToolChoice:
    tool: str
    rationale: str


SERVICE_MITRE: dict[str, MitreMapping] = {
    "ssh": MitreMapping("Discovery", "T1046", "Network Service Discovery"),
    "http": MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "https": MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "http-proxy": MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "ssl/http": MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "ssl/https": MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "http-alt": MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "https-alt": MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "mysql": MitreMapping("Collection", "T1213", "Data from Information Repositories"),
    "mariadb": MitreMapping("Collection", "T1213", "Data from Information Repositories"),
    "ms-sql": MitreMapping("Collection", "T1213", "Data from Information Repositories"),
    "rdp": MitreMapping("Discovery", "T1046", "Network Service Discovery"),
    "ftp": MitreMapping("Discovery", "T1046", "Network Service Discovery"),
}

DEFAULT_MITRE = MitreMapping("Discovery", "T1046", "Network Service Discovery")
KEV_MITRE = MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application")
DIRECTORY_ENUMERATION_MITRE = MitreMapping("Discovery", "T1083", "File and Directory Discovery")
NUCLEI_MITRE = MitreMapping("Initial Access", "T1190", "Exploit Public-Facing Application")


def normalize_service(service: str | None) -> str:
    if not service:
        return ""
    return service.lower().split()[0].split("/")[0].split(":")[0]


def is_web_port(port: int | None, service: str | None) -> bool:
    if port in HTTP_PORTS:
        return True
    svc = normalize_service(service)
    return svc in WEB_SERVICES or svc.startswith("http")


def has_successful_tool(tool_results: list[dict], tool_name: str, port: int | None) -> bool:
    for row in tool_results:
        if row.get("tool_name") != tool_name or not row.get("success"):
            continue
        if port is None or row.get("open_port_id") is None:
            return True
        if row.get("port") == port:
            return True
    return False


def map_service_to_mitre(
    service: str | None,
    port: int | None,
    *,
    kev_present: bool = False,
    enrichment_tactic: str | None = None,
    enrichment_technique: str | None = None,
) -> MitreMapping:
    if enrichment_tactic and enrichment_technique:
        return MitreMapping(enrichment_tactic, enrichment_technique, enrichment_technique)

    if kev_present:
        return KEV_MITRE

    svc = normalize_service(service)
    if svc in SERVICE_MITRE:
        return SERVICE_MITRE[svc]

    if is_web_port(port, service):
        return SERVICE_MITRE["http"]

    if port == 22:
        return SERVICE_MITRE["ssh"]
    if port == 3306:
        return SERVICE_MITRE["mysql"]

    return DEFAULT_MITRE


def map_tool_to_mitre(tool_name: str | None, evidence_type: str | None = None) -> MitreMapping:
    tool = (tool_name or "").strip().lower()
    evidence = (evidence_type or "").strip().lower()

    if tool in {"dirb", "dirb_safe"} or evidence == "content_discovery":
        return DIRECTORY_ENUMERATION_MITRE
    if tool in {"nuclei", "nuclei_safe"} or evidence in {"vulnerability", "vulnerability_scan_negative"}:
        return NUCLEI_MITRE
    if tool in {"httpx", "httpx_basic"} or evidence == "http_service":
        return SERVICE_MITRE["http"]
    if tool in {"ssh-enum", "ssh_enum"} or evidence == "ssh_service":
        return SERVICE_MITRE["ssh"]
    if tool in {"mysql-info", "mysql_info"} or evidence == "database_service":
        return SERVICE_MITRE["mysql"]
    return DEFAULT_MITRE


def select_next_tool(
    port: int | None,
    service: str | None,
    tool_results: list[dict],
) -> ToolChoice:
    """
    Tool routing (safe enumeration only):
    - HTTP/HTTPS → httpx
    - Web alive (httpx success) → nuclei
    - MySQL → mysql-info
    - SSH → ssh-enum
    - otherwise → none
    """
    svc = normalize_service(service)

    if is_web_port(port, service):
        if has_successful_tool(tool_results, "httpx", port):
            return ToolChoice("nuclei", f"Web service on port {port} probed; run nuclei templates")
        return ToolChoice("httpx", f"HTTP/HTTPS service on port {port}; probe with httpx")

    if port == 3306 or "mysql" in svc:
        return ToolChoice("mysql-info", f"MySQL on port {port}; safe mysql-info enumeration")

    if port == 22 or svc == "ssh":
        return ToolChoice("ssh-enum", f"SSH on port {port}; safe ssh-enum (no brute force)")

    return ToolChoice("none", "No safe follow-up tool mapping for this port/service")

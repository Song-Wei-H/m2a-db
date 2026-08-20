from __future__ import annotations

import ipaddress
from typing import Any


ACTION_BY_TOOL = {
    "http_security_headers": "http_security_headers.collect.v1",
    "nuclei_safe": "nuclei.safe_scan.v1",
    "dns_metadata": "dns.metadata_collect.v1",
    "tls_certificate": "tls.certificate_collect.v1",
    "nmap_service": "nmap.service_fingerprint.v1",
    "httpx_basic": "httpx.web_probe.v1",
}
TOOL_BY_ACTION = {action: tool for tool, action in ACTION_BY_TOOL.items()}
PROTECTED_ACTION_TOOLS = frozenset(ACTION_BY_TOOL)

HEADER_IDENTITY = (
    "builtin:http-security-headers:head-root:user-agent=M2A-Worker/1:"
    "connection=close:timeout=10:tls-verify=false:redirect=false:body=false:v2"
)
NUCLEI_IDENTITY = (
    "argv:nuclei:-u:{canonical_url}:-severity:critical,high:-rl:5:"
    "-timeout:5:-retries:0:-no-color:v2"
)
DNS_IDENTITY = (
    "builtin:dns-metadata:getaddrinfo=A,AAAA:ptr=ip-only:fqdn=true:"
    "resolver=system:retry=0:timeout=worker-request-ceiling:v2"
)
TLS_IDENTITY = (
    "builtin:tls-certificate:tcp-connect:tls-client:sni={sni}:timeout=10:"
    "tls-verify=false:certificate-sha256=true:v2"
)
NMAP_IDENTITY = (
    "argv:nmap:-sV:{target}:ports=default:no-script:no-port-override:"
    "timeout=180:nmap-default-retry:v2"
)
HTTPX_IDENTITY = (
    "argv:httpx:-u:{canonical_url}:-json:-title:-tech-detect:-status-code:"
    "method=probe:path=/:redirect=false:retry=httpx-default:timeout=180:v2"
)
ACTION_IDENTITIES = {
    "http_security_headers.collect.v1": HEADER_IDENTITY,
    "nuclei.safe_scan.v1": NUCLEI_IDENTITY,
    "dns.metadata_collect.v1": DNS_IDENTITY,
    "tls.certificate_collect.v1": TLS_IDENTITY,
    "nmap.service_fingerprint.v1": NMAP_IDENTITY,
    "httpx.web_probe.v1": HTTPX_IDENTITY,
}
ACTION_TEMPLATES = {
    "http_security_headers.collect.v1": "http_security_headers_v2",
    "nuclei.safe_scan.v1": "nuclei_safe_v2",
    "dns.metadata_collect.v1": "dns_metadata_v2",
    "tls.certificate_collect.v1": "tls_certificate_v2",
    "nmap.service_fingerprint.v1": "nmap_service_v2",
    "httpx.web_probe.v1": "httpx_web_probe_v2",
}


def canonical_http_url(*, target: str, port: int | None, service: str | None, path: str = "/") -> str:
    host = target.strip()
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host}]"
    except ValueError:
        pass
    selected_port = port or 80
    service_name = (service or "").lower()
    scheme = "https" if selected_port in {443, 8443} or any(
        marker in service_name for marker in ("https", "ssl", "tls")
    ) else "http"
    normalized_path = "/" + path.lstrip("/")
    return f"{scheme}://{host}:{selected_port}{normalized_path}"


def canonical_action_parameters(
    *, action_id: str, target: str, port: int | None,
    protocol: str | None, service: str | None,
) -> dict[str, Any]:
    if action_id not in TOOL_BY_ACTION:
        raise ValueError(f"Unknown migrated action {action_id!r}")
    if action_id == "dns.metadata_collect.v1":
        host = target.strip()
        return {
            "host": host, "normalized_hostname": host.rstrip(".").lower(),
            "port": None, "protocol": protocol or None, "service": service or None,
            "target": host,
            "query_behavior": {
                "address_families": ["A", "AAAA"], "canonical_name": True,
                "ptr_for_ip_target": True, "resolver": "system",
                "retry_ceiling": 0, "timeout": "worker-request-ceiling",
            },
        }
    if action_id == "tls.certificate_collect.v1":
        selected_port = port or 443
        host = target.strip()
        return {
            "certificate_sha256": True, "host": host, "port": selected_port,
            "protocol": protocol or None, "protocol_expectation": "tls",
            "service": service or None, "sni": host, "target": host,
            "timeout_seconds": 10, "tls_verify": False,
        }
    if action_id == "nmap.service_fingerprint.v1":
        host = target.strip()
        return {
            "address": host,
            "argv": ["nmap", "-sV", host],
            "host_discovery": "nmap-default",
            "port_scope": "nmap-default-no-port-override",
            "protocol": protocol or None,
            "requested_port": port,
            "retry_behavior": "nmap-default",
            "scan_type": "service-version-detection",
            "scripts": [],
            "service": service or None,
            "target": host,
            "timeout_seconds": 180,
        }
    if action_id == "httpx.web_probe.v1":
        selected_port = port or 80
        host = target.strip()
        url = canonical_http_url(target=host, port=selected_port, service=service)
        return {
            "argv": ["httpx", "-u", url, "-json", "-title", "-tech-detect", "-status-code"],
            "canonical_url": url,
            "host": host,
            "method": "httpx-default-probe",
            "path": "/",
            "port": selected_port,
            "protocol": protocol or None,
            "redirect_policy": {
                "follow": False, "max_redirects": 0, "cross_host": False,
                "cross_port": False, "cross_scheme": False,
            },
            "retry_behavior": "httpx-default",
            "scheme": url.split(":", 1)[0],
            "service": service or None,
            "target": host,
            "timeout_seconds": 180,
        }
    selected_port = port or 80
    url = canonical_http_url(target=target, port=selected_port, service=service)
    parameters: dict[str, Any] = {
        "canonical_url": url,
        "host": target.strip(),
        "path": "/",
        "port": selected_port,
        "protocol": protocol or None,
        "scheme": url.split(":", 1)[0],
        "service": service or None,
        "target": target.strip(),
    }
    if action_id == "http_security_headers.collect.v1":
        parameters["collector"] = {
            "body_read": False, "connection": "close", "follow_redirects": False,
            "method": "HEAD", "timeout_seconds": 10, "tls_verify": False,
            "user_agent": "M2A-Worker/1",
        }
    else:
        parameters["argv"] = [
            "nuclei", "-u", url, "-severity", "critical,high", "-rl", "5",
            "-timeout", "5", "-retries", "0", "-no-color",
        ]
    return parameters

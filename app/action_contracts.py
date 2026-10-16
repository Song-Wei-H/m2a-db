from __future__ import annotations

import ipaddress
from typing import Any


ACTION_BY_TOOL = {
    "lab_valid_account_access": "lab.valid_account_access.v1",
    "lab_fixed_python_execution": "lab.fixed_python_execution.v1",
    "http_security_headers": "http_security_headers.collect.v1",
    "nuclei_safe": "nuclei.safe_scan.v1",
    "dns_metadata": "dns.metadata_collect.v1",
    "tls_certificate": "tls.certificate_collect.v1",
    "nmap_service": "nmap.service_fingerprint.v1",
    "httpx_basic": "httpx.web_probe.v1",
    "ssh-enum": "ssh.algorithms_enum.v1",
    "mysql-info": "mysql.server_info.v1",
}
# M2A engagement-depth requirements are part of the immutable server-side
# Action Contract. LLM proposals cannot provide or override these values.
ACTION_REQUIRED_ATTACK_DEPTH = {
    "lab.valid_account_access.v1": 2,  # fixed, lab-only valid-account login and protected-resource check
    "lab.fixed_python_execution.v1": 3,  # fixed, session-bound target-side Python execution emulation
    "http_security_headers.collect.v1": 1,  # bounded HEAD-only configuration check
    "nuclei.safe_scan.v1": 1,  # fixed critical/high safe-scan contract
    "dns.metadata_collect.v1": 1,  # bounded DNS metadata collection
    "tls.certificate_collect.v1": 1,  # certificate metadata only
    "nmap.service_fingerprint.v1": 1,  # service/version discovery; no scripts/port override
    "httpx.web_probe.v1": 1,  # bounded root-path HTTP probe; no redirects
    "ssh.algorithms_enum.v1": 1,  # unauthenticated SSH algorithm enumeration only
    "mysql.server_info.v1": 1,  # unauthenticated server metadata only
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
SSH_IDENTITY = (
    "argv:nmap:--script:ssh2-enum-algos:-p:{port}:{target}:"
    "algorithm-enumeration-only:timeout=180:nmap-default-retry:v2"
)
MYSQL_IDENTITY = (
    "argv:nmap:--script:mysql-info:-p:{port}:{target}:"
    "server-info-only:no-auth:timeout=180:nmap-default-retry:v2"
)
LAB_VALID_ACCOUNT_IDENTITY = (
    "builtin:lab-valid-account-access:10.56.66.119:18080:"
    "post-/lab/auth/login:get-/lab/protected:credentials=worker-env:ttl=60:v1"
)
LAB_FIXED_PYTHON_EXECUTION_IDENTITY = (
    "builtin:lab-fixed-python:10.56.66.119:18080:"
    "post-/lab/auth/login:post-/lab/execute:script=l3-fixed-python-v1:ttl=60:v1"
)
ACTION_IDENTITIES = {
    "lab.valid_account_access.v1": LAB_VALID_ACCOUNT_IDENTITY,
    "lab.fixed_python_execution.v1": LAB_FIXED_PYTHON_EXECUTION_IDENTITY,
    "http_security_headers.collect.v1": HEADER_IDENTITY,
    "nuclei.safe_scan.v1": NUCLEI_IDENTITY,
    "dns.metadata_collect.v1": DNS_IDENTITY,
    "tls.certificate_collect.v1": TLS_IDENTITY,
    "nmap.service_fingerprint.v1": NMAP_IDENTITY,
    "httpx.web_probe.v1": HTTPX_IDENTITY,
    "ssh.algorithms_enum.v1": SSH_IDENTITY,
    "mysql.server_info.v1": MYSQL_IDENTITY,
}
ACTION_TEMPLATES = {
    "lab.valid_account_access.v1": "lab_valid_account_access_v1",
    "lab.fixed_python_execution.v1": "lab_fixed_python_execution_v1",
    "http_security_headers.collect.v1": "http_security_headers_v2",
    "nuclei.safe_scan.v1": "nuclei_safe_v2",
    "dns.metadata_collect.v1": "dns_metadata_v2",
    "tls.certificate_collect.v1": "tls_certificate_v2",
    "nmap.service_fingerprint.v1": "nmap_service_v2",
    "httpx.web_probe.v1": "httpx_web_probe_v2",
    "ssh.algorithms_enum.v1": "ssh_algorithms_enum_v2",
    "mysql.server_info.v1": "mysql_server_info_v2",
}
ACTION_PARAMETER_SCHEMAS = {
    "lab.valid_account_access.v1": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "target", "host", "port", "protocol", "service", "login_method",
            "login_path", "protected_method", "protected_path", "session_ttl_seconds",
        ],
        "properties": {
            "target": {"const": "10.56.66.119"},
            "host": {"const": "10.56.66.119"},
            "port": {"const": 18080},
            "protocol": {"const": "tcp"},
            "service": {"const": "http"},
            "login_method": {"const": "POST"},
            "login_path": {"const": "/lab/auth/login"},
            "protected_method": {"const": "GET"},
            "protected_path": {"const": "/lab/protected"},
            "session_ttl_seconds": {"const": 60},
        },
    },
    "lab.fixed_python_execution.v1": {
        "type": "object",
        "additionalProperties": False,
        "required": ["target", "host", "port", "protocol", "service", "login_method",
                     "login_path", "execute_method", "execute_path", "script_id",
                     "script_sha256", "expected_result", "session_ttl_seconds"],
        "properties": {
            "target": {"const": "10.56.66.119"}, "host": {"const": "10.56.66.119"},
            "port": {"const": 18080}, "protocol": {"const": "tcp"}, "service": {"const": "http"},
            "login_method": {"const": "POST"}, "login_path": {"const": "/lab/auth/login"},
            "execute_method": {"const": "POST"}, "execute_path": {"const": "/lab/execute"},
            "script_id": {"const": "gade-controlled-python-execution-v1"},
            "script_sha256": {"const": "b6d8391432ad8f0f993a51c2c35e13d86354f3d0220c3e1c71d69e82a5f164bb"},
            "expected_result": {"const": 39}, "session_ttl_seconds": {"const": 60},
        },
    },
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
    if action_id == "lab.valid_account_access.v1":
        host = target.strip()
        if host != "10.56.66.119" or port != 18080 or (protocol or "").lower() != "tcp" or (service or "").lower() != "http":
            raise ValueError("L2 valid-account action is fixed to the authorized Lab HTTP endpoint")
        return {
            "target": host, "host": host, "port": 18080,
            "protocol": "tcp", "service": "http",
            "login_method": "POST", "login_path": "/lab/auth/login",
            "protected_method": "GET", "protected_path": "/lab/protected",
            "session_ttl_seconds": 60,
        }
    if action_id == "lab.fixed_python_execution.v1":
        host = target.strip()
        if host != "10.56.66.119" or port != 18080 or (protocol or "").lower() != "tcp" or (service or "").lower() != "http":
            raise ValueError("L3 Python execution action is fixed to the authorized Lab HTTP endpoint")
        return {
            "target": host, "host": host, "port": 18080, "protocol": "tcp", "service": "http",
            "login_method": "POST", "login_path": "/lab/auth/login",
            "execute_method": "POST", "execute_path": "/lab/execute",
            "script_id": "gade-controlled-python-execution-v1",
            "script_sha256": "b6d8391432ad8f0f993a51c2c35e13d86354f3d0220c3e1c71d69e82a5f164bb",
            "expected_result": 39, "session_ttl_seconds": 60,
        }
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
    if action_id in {"ssh.algorithms_enum.v1", "mysql.server_info.v1"}:
        host = target.strip()
        service_name = (service or "").strip().lower()
        is_ssh = service_name == "ssh" or port == 22
        is_mysql = service_name in {"mysql", "mariadb"} or port == 3306
        if action_id == "ssh.algorithms_enum.v1":
            if not is_ssh or is_mysql:
                raise ValueError("ssh action is not applicable to the supplied service evidence")
            selected_port, script, purpose = port or 22, "ssh2-enum-algos", "algorithm-enumeration-only"
        else:
            if not is_mysql or is_ssh:
                raise ValueError("mysql action is not applicable to the supplied service evidence")
            selected_port, script, purpose = port or 3306, "mysql-info", "server-info-only"
        return {
            "argv": ["nmap", "--script", script, "-p", str(selected_port), host],
            "authentication": "none",
            "host": host,
            "port": selected_port,
            "protocol": protocol or None,
            "retry_behavior": "nmap-default",
            "scan_type": purpose,
            "script": script,
            "scripts": [script],
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

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any


HOME_LAB_EXPLORATORY = os.environ.get("GADE_HOME_LAB_EXPLORATORY") == "1"
OFFICE_DOCKER_LAB = os.environ.get("GADE_OFFICE_DOCKER_LAB") == "1"
if HOME_LAB_EXPLORATORY and OFFICE_DOCKER_LAB:
    raise RuntimeError("home and office synthetic lab profiles are mutually exclusive")
OFFICE_DOCKER_LAB_TARGET = os.environ.get("GADE_OFFICE_DOCKER_LAB_TARGET", "").strip()
OFFICE_DOCKER_LAB_PORT = os.environ.get("GADE_OFFICE_DOCKER_LAB_PORT", "18081").strip()
if OFFICE_DOCKER_LAB:
    try:
        if ipaddress.ip_address(OFFICE_DOCKER_LAB_TARGET).version != 4 or OFFICE_DOCKER_LAB_PORT != "18081":
            raise ValueError
    except ValueError as exc:
        raise RuntimeError("office Docker lab requires an explicit IPv4 target and the reviewed gateway port 18081") from exc
SYNTHETIC_LAB_PROFILE = HOME_LAB_EXPLORATORY or OFFICE_DOCKER_LAB
LAB_TARGET = ("127.0.0.1" if HOME_LAB_EXPLORATORY else
              OFFICE_DOCKER_LAB_TARGET if OFFICE_DOCKER_LAB else
              os.environ.get("GADE_LAB_TARGET_HOST", "127.0.0.1").strip())
LAB_PORT = 18080 if HOME_LAB_EXPLORATORY else (18081 if OFFICE_DOCKER_LAB else 18080)
try:
    if ipaddress.ip_address(LAB_TARGET).version != 4:
        raise ValueError
except ValueError as exc:
    raise RuntimeError("The selected isolated lab target must be an explicit IPv4 address") from exc
HOME_NUCLEI_TEMPLATE_PATH = "/home/kali/gade-approved-nuclei/gade-home-exposed-backup-index.yaml"
HOME_NUCLEI_TEMPLATE_SHA256 = "7454a7f7f5d4ae47a140021d4e6754e56abe0f737ee514637c3a42c03f86320f"
SCENARIO_B_NUCLEI_PROFILE = "gade-b-safe-positive-negative-v1"
SCENARIO_B_NUCLEI_PROFILE_ENABLED = os.environ.get("GADE_NUCLEI_PROFILE") == "scenario-b-fixed-v1"
SCENARIO_B_NUCLEI_TARGET = os.environ.get("GADE_SCENARIO_B_TARGET_HOST", "").strip()
if SCENARIO_B_NUCLEI_PROFILE_ENABLED:
    try:
        if not SCENARIO_B_NUCLEI_TARGET or ipaddress.ip_address(SCENARIO_B_NUCLEI_TARGET).version != 4:
            raise ValueError
    except ValueError as exc:
        raise RuntimeError("Scenario B requires an explicit IPv4 target in GADE_SCENARIO_B_TARGET_HOST") from exc
SCENARIO_B_NUCLEI_TEMPLATE_DIR = "/opt/gade-approved-nuclei/scenario-b-v1"
SCENARIO_B_NUCLEI_MANIFEST_PATH = f"{SCENARIO_B_NUCLEI_TEMPLATE_DIR}/manifest.json"
SCENARIO_B_NUCLEI_TEMPLATE_IDS = (
    "gade-b-positive-backup-index-v1",
    "gade-b-negative-control-v1",
)
SCENARIO_B_NUCLEI_TEMPLATE_FILES = (
    "gade-b-positive-backup-index.yaml",
    "gade-b-negative-control.yaml",
)
SCENARIO_B_NUCLEI_TEMPLATE_SHA256 = {
    "gade-b-positive-backup-index.yaml": "bf20ee8fb0ca44eca79b4118dcb9b707b5421298fcd791b4656e35e46f684bbb",
    "gade-b-negative-control.yaml": "b34fdbe843a526de8ecbbb0a497540b38073b23e88c683261ede6f5d2ec1121c",
}
SCENARIO_B_NUCLEI_MANIFEST_SHA256 = "2b66f8d55124b41f87eaca7ebad84792b5a74c11de83bb47721fea5949748548"
SCENARIO_B_NUCLEI_BUNDLE_SHA256 = "6dfdc4f60b37222e035ce3fac8ba7c2e8c55475b816b406b04308441de843727"
SCENARIO_B_NUCLEI_TARGET_TRUTH_PATH = "lab/mode-b-target/nuclei-target-truth-v1.json"
SCENARIO_B_NUCLEI_TARGET_TRUTH_SHA256 = os.environ.get("GADE_SCENARIO_B_TARGET_TRUTH_SHA256", "").strip()
if SCENARIO_B_NUCLEI_PROFILE_ENABLED and not re.fullmatch(r"[0-9a-f]{64}", SCENARIO_B_NUCLEI_TARGET_TRUTH_SHA256):
    raise RuntimeError("Scenario B requires a locally rendered and SHA-256 pinned target-truth file")
HOME_ADVANCED_ACTIONS = {
    "lab_synthetic_canary_access": ("lab.synthetic_canary_access.v1", 5, "l5-canary"),
    "lab_simulated_visibility_comparison": ("lab.simulated_visibility_comparison.v1", 5, "l5-visibility"),
    "lab_synthetic_node_discovery": ("lab.synthetic_node_discovery.v1", 6, "l6-discovery"),
    "lab_synthetic_node_session": ("lab.synthetic_node_session.v1", 6, "l6-session"),
    "lab_synthetic_collection": ("lab.synthetic_collection.v1", 7, "l7-collection"),
    "lab_local_c2_simulation": ("lab.local_c2_simulation.v1", 7, "l7-c2"),
    "lab_synthetic_receiver_transfer": ("lab.synthetic_receiver_transfer.v1", 7, "l7-transfer"),
    "lab_reversible_impact_simulation": ("lab.reversible_impact_simulation.v1", 7, "l7-impact"),
}


ACTION_BY_TOOL = {
    "lab_synthetic_role_lease": "lab.synthetic_role_lease.v1",
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
if SYNTHETIC_LAB_PROFILE:
    ACTION_BY_TOOL.update({tool: action for tool, (action, _depth, _path) in HOME_ADVANCED_ACTIONS.items()})
# M2A engagement-depth requirements are part of the immutable server-side
# Action Contract. LLM proposals cannot provide or override these values.
ACTION_REQUIRED_ATTACK_DEPTH = {
    "lab.synthetic_role_lease.v1": 4,  # reversible application-level role lease, home lab only
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
if SYNTHETIC_LAB_PROFILE:
    ACTION_REQUIRED_ATTACK_DEPTH.update({action: depth for action, depth, _path in HOME_ADVANCED_ACTIONS.values()})
TOOL_BY_ACTION = {action: tool for tool, action in ACTION_BY_TOOL.items()}
PROTECTED_ACTION_TOOLS = frozenset(ACTION_BY_TOOL)

HEADER_IDENTITY = (
    "builtin:http-security-headers:head-root:user-agent=M2A-Worker/1:"
    "connection=close:timeout=10:tls-verify=false:redirect=false:body=false:v2"
)
NUCLEI_IDENTITY = (
    f"argv:nuclei-home-fixed-v1:template-sha256:{HOME_NUCLEI_TEMPLATE_SHA256}:stdin=devnull"
    if HOME_LAB_EXPLORATORY else
    f"argv:nuclei:{SCENARIO_B_NUCLEI_PROFILE}:bundle-sha256:{SCENARIO_B_NUCLEI_BUNDLE_SHA256}:"
    f"target=http://{SCENARIO_B_NUCLEI_TARGET}:18080/:severity=info:rate=2:concurrency=1:timeout=5:retry=0:"
    "no-update=true:no-interactsh=true:jsonl=true:silent=true:v1"
    if SCENARIO_B_NUCLEI_PROFILE_ENABLED else
    "argv:nuclei:-u:{canonical_url}:-severity:critical,high:-rl:5:"
    "-timeout:5:-retries:0:-no-color:v2"
)


def nuclei_fixed_argv(url: str) -> list[str]:
    if SCENARIO_B_NUCLEI_PROFILE_ENABLED:
        expected_url = f"http://{SCENARIO_B_NUCLEI_TARGET}:18080/"
        if url != expected_url:
            raise ValueError("Scenario B Nuclei is fixed to the reviewed synthetic target URL")
        return [
            "nuclei", "-u", expected_url, "-t", SCENARIO_B_NUCLEI_TEMPLATE_DIR,
            "-severity", "info", "-rl", "2", "-c", "1", "-bs", "1",
            "-timeout", "5", "-retries", "0", "-duc", "-ni", "-jsonl", "-silent", "-no-color",
        ]
    argv = ["nuclei", "-u", url]
    if HOME_LAB_EXPLORATORY:
        argv += ["-t", HOME_NUCLEI_TEMPLATE_PATH]
    argv += ["-severity", "critical,high", "-rl", "5", "-timeout", "5",
             "-retries", "0", "-no-color"]
    if HOME_LAB_EXPLORATORY:
        argv += ["-duc", "-ni", "-auth=false"]
    return argv
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
    f"builtin:lab-valid-account-access:{LAB_TARGET}:{LAB_PORT}:"
    "post-/lab/auth/login:get-/lab/protected:credentials=worker-env:ttl=60:v1"
)
LAB_FIXED_PYTHON_EXECUTION_IDENTITY = (
    f"builtin:lab-fixed-python:{LAB_TARGET}:{LAB_PORT}:"
    "post-/lab/auth/login:post-/lab/execute:script=l3-fixed-python-v1:ttl=60:v1"
)
LAB_SYNTHETIC_ROLE_LEASE_IDENTITY = (
    f"builtin:lab-synthetic-role-lease:{LAB_TARGET}:{LAB_PORT}:"
    "post-/lab/auth/login:post-/lab/l4/role-lease:"
    "get-/lab/l4/protected:role=synthetic-lab-operator:ttl=300:v1"
)
ACTION_IDENTITIES = {
    "lab.synthetic_role_lease.v1": LAB_SYNTHETIC_ROLE_LEASE_IDENTITY,
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
if SYNTHETIC_LAB_PROFILE:
    ACTION_IDENTITIES.update({action: f"builtin:isolated-advanced:{path}:{LAB_TARGET}:{LAB_PORT}:v1"
                              for action, _depth, path in HOME_ADVANCED_ACTIONS.values()})
ACTION_TEMPLATES = {
    "lab.synthetic_role_lease.v1": "lab_synthetic_role_lease_v1",
    "lab.valid_account_access.v1": "lab_valid_account_access_v1",
    "lab.fixed_python_execution.v1": "lab_fixed_python_execution_v1",
    "http_security_headers.collect.v1": "http_security_headers_v2",
    "nuclei.safe_scan.v1": "nuclei_safe_home_v1" if HOME_LAB_EXPLORATORY else "nuclei_safe_v2",
    "dns.metadata_collect.v1": "dns_metadata_v2",
    "tls.certificate_collect.v1": "tls_certificate_v2",
    "nmap.service_fingerprint.v1": "nmap_service_v2",
    "httpx.web_probe.v1": "httpx_web_probe_v2",
    "ssh.algorithms_enum.v1": "ssh_algorithms_enum_v2",
    "mysql.server_info.v1": "mysql_server_info_v2",
}
if SCENARIO_B_NUCLEI_PROFILE_ENABLED:
    ACTION_TEMPLATES["nuclei.safe_scan.v1"] = "nuclei_safe_scenario_b_v1"
if SYNTHETIC_LAB_PROFILE:
    ACTION_TEMPLATES.update({action: action.replace(".", "_")
                             for action, _depth, _path in HOME_ADVANCED_ACTIONS.values()})
ACTION_PARAMETER_SCHEMAS = {
    "lab.synthetic_role_lease.v1": {
        "type": "object", "additionalProperties": False,
        "required": ["target", "host", "port", "protocol", "service", "login_method",
                     "login_path", "lease_method", "lease_path", "protected_method",
                     "protected_path", "role", "lease_ttl_seconds", "session_ttl_seconds"],
        "properties": {
            "target": {"const": LAB_TARGET}, "host": {"const": LAB_TARGET},
            "port": {"const": LAB_PORT}, "protocol": {"const": "tcp"},
            "service": {"const": "http"}, "login_method": {"const": "POST"},
            "login_path": {"const": "/lab/auth/login"}, "lease_method": {"const": "POST"},
            "lease_path": {"const": "/lab/l4/role-lease"},
            "protected_method": {"const": "GET"},
            "protected_path": {"const": "/lab/l4/protected"},
            "role": {"const": "synthetic-lab-operator"},
            "lease_ttl_seconds": {"const": 300}, "session_ttl_seconds": {"const": 60},
        },
    },
    "lab.valid_account_access.v1": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "target", "host", "port", "protocol", "service", "login_method",
            "login_path", "protected_method", "protected_path", "session_ttl_seconds",
        ],
        "properties": {
            "target": {"const": LAB_TARGET},
            "host": {"const": LAB_TARGET},
            "port": {"const": LAB_PORT},
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
            "target": {"const": LAB_TARGET}, "host": {"const": LAB_TARGET},
            "port": {"const": LAB_PORT}, "protocol": {"const": "tcp"}, "service": {"const": "http"},
            "login_method": {"const": "POST"}, "login_path": {"const": "/lab/auth/login"},
            "execute_method": {"const": "POST"}, "execute_path": {"const": "/lab/execute"},
            "script_id": {"const": "gade-controlled-python-execution-v1"},
            "script_sha256": {"const": "b6d8391432ad8f0f993a51c2c35e13d86354f3d0220c3e1c71d69e82a5f164bb"},
            "expected_result": {"const": 39}, "session_ttl_seconds": {"const": 60},
        },
    },
}
if SCENARIO_B_NUCLEI_PROFILE_ENABLED:
    _scenario_b_url = f"http://{SCENARIO_B_NUCLEI_TARGET}:18080/"
    _scenario_b_nuclei_parameters = {
        "target": SCENARIO_B_NUCLEI_TARGET, "host": SCENARIO_B_NUCLEI_TARGET, "port": 18080,
        "protocol": "tcp", "service": "http", "canonical_url": _scenario_b_url,
        "scheme": "http", "path": "/", "argv": nuclei_fixed_argv(_scenario_b_url),
        "template_profile": SCENARIO_B_NUCLEI_PROFILE,
        "template_bundle_sha256": SCENARIO_B_NUCLEI_BUNDLE_SHA256,
        "template_ids": list(SCENARIO_B_NUCLEI_TEMPLATE_IDS), "severity_selector": "info",
        "timeout_seconds": 5, "retry_behavior": "no-retry",
    }
    ACTION_PARAMETER_SCHEMAS["nuclei.safe_scan.v1"] = {
        "type": "object", "additionalProperties": False,
        "required": sorted(_scenario_b_nuclei_parameters),
        "properties": {key: {"const": value} for key, value in _scenario_b_nuclei_parameters.items()},
    }
if SYNTHETIC_LAB_PROFILE:
    for _action, _depth, _path in HOME_ADVANCED_ACTIONS.values():
        _fixed = {"target": LAB_TARGET, "host": LAB_TARGET, "port": LAB_PORT,
                  "protocol": "tcp", "service": "http", "login_method": "POST",
                  "login_path": "/lab/auth/login", "action_method": "POST",
                  "action_path": f"/lab/advanced/{_path}", "request_body": {},
                  "session_ttl_seconds": 60}
        ACTION_PARAMETER_SCHEMAS[_action] = {
            "type": "object", "additionalProperties": False,
            "required": list(_fixed),
            "properties": {key: {"const": value} for key, value in _fixed.items()},
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
    if SYNTHETIC_LAB_PROFILE and action_id in {item[0] for item in HOME_ADVANCED_ACTIONS.values()}:
        host = target.strip()
        if (host != LAB_TARGET or port != LAB_PORT or (protocol or "").lower() != "tcp"
                or (service or "").lower() != "http"):
            raise ValueError("advanced synthetic action is fixed to the selected isolated Lab endpoint")
        return {key: value["const"] for key, value in ACTION_PARAMETER_SCHEMAS[action_id]["properties"].items()}
    if action_id == "nuclei.safe_scan.v1" and SCENARIO_B_NUCLEI_PROFILE_ENABLED:
        if (target.strip() != SCENARIO_B_NUCLEI_TARGET or port != 18080
                or (protocol or "").lower() != "tcp" or (service or "").lower() != "http"):
            raise ValueError("Scenario B Nuclei is fixed to the reviewed isolated target HTTP endpoint")
        return dict(_scenario_b_nuclei_parameters)
    if action_id == "lab.synthetic_role_lease.v1":
        host = target.strip()
        if (not SYNTHETIC_LAB_PROFILE or host != LAB_TARGET or port != LAB_PORT
                or (protocol or "").lower() != "tcp" or (service or "").lower() != "http"):
            raise ValueError("L4 synthetic role lease is fixed to the selected isolated Lab endpoint")
        return {
            "target": host, "host": host, "port": LAB_PORT,
            "protocol": "tcp", "service": "http", "login_method": "POST",
            "login_path": "/lab/auth/login", "lease_method": "POST",
            "lease_path": "/lab/l4/role-lease", "protected_method": "GET",
            "protected_path": "/lab/l4/protected", "role": "synthetic-lab-operator",
            "lease_ttl_seconds": 300, "session_ttl_seconds": 60,
        }
    if action_id == "lab.valid_account_access.v1":
        host = target.strip()
        if host != LAB_TARGET or port != LAB_PORT or (protocol or "").lower() != "tcp" or (service or "").lower() != "http":
            raise ValueError("L2 valid-account action is fixed to the authorized Lab HTTP endpoint")
        return {
            "target": host, "host": host, "port": LAB_PORT,
            "protocol": "tcp", "service": "http",
            "login_method": "POST", "login_path": "/lab/auth/login",
            "protected_method": "GET", "protected_path": "/lab/protected",
            "session_ttl_seconds": 60,
        }
    if action_id == "lab.fixed_python_execution.v1":
        host = target.strip()
        if host != LAB_TARGET or port != LAB_PORT or (protocol or "").lower() != "tcp" or (service or "").lower() != "http":
            raise ValueError("L3 Python execution action is fixed to the authorized Lab HTTP endpoint")
        return {
            "target": host, "host": host, "port": LAB_PORT, "protocol": "tcp", "service": "http",
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
        parameters["argv"] = nuclei_fixed_argv(url)
    return parameters

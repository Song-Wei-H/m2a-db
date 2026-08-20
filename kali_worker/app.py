from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import shlex
import socket
import ssl
import subprocess
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict
from app.action_contracts import (
    ACTION_IDENTITIES, ACTION_BY_TOOL, canonical_action_parameters, PROTECTED_ACTION_TOOLS,
)

app = FastAPI(title="M2A Kali Worker", version="evidence-tools-v1")

ALLOWED_TOOLS = {
    "nmap_service", "httpx_basic", "nuclei_safe", "dirb_safe",
    "ssh-enum", "mysql-info", "tls_certificate",
    "http_security_headers", "dns_metadata",
}
SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "referrer-policy",
    "permissions-policy", "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)
EVIDENCE_HEADERS = SECURITY_HEADERS + ("server", "cache-control", "content-type")


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str
    target: str
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    action_id: str | None = None
    execution_identity: str | None = None
    authorization_parameters: dict[str, Any] | None = None
    authorization_parameters_hash: str | None = None


def canonical_parameters(req: ExecuteRequest) -> dict[str, Any]:
    if req.action_id is None:
        return {"port": req.port, "protocol": req.protocol or None,
                "service": req.service or None, "target": req.target.strip()}
    return canonical_action_parameters(action_id=req.action_id, target=req.target, port=req.port,
                                       protocol=req.protocol, service=req.service)


def parameters_hash(parameters: dict[str, Any]) -> str:
    payload = json.dumps(parameters, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def validate_execution_identity(req: ExecuteRequest) -> str | None:
    if req.action_id is None:
        if req.tool in PROTECTED_ACTION_TOOLS:
            return "authorization required for migrated action"
        return None
    expected_identity = ACTION_IDENTITIES.get(req.action_id)
    if expected_identity is None or expected_identity != req.execution_identity:
        return "execution identity mismatch"
    parameters = canonical_parameters(req)
    if req.authorization_parameters != parameters or req.authorization_parameters_hash != parameters_hash(parameters):
        return "authorization parameter identity mismatch"
    expected_tool = {action: tool for tool, action in ACTION_BY_TOOL.items()}[req.action_id]
    if req.tool != expected_tool:
        return "authorized action does not match tool"
    return None


def resolved_addresses(target: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return [ipaddress.ip_address(target)]
    except ValueError:
        addresses = {
            ipaddress.ip_address(row[4][0])
            for row in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            if row[0] in {socket.AF_INET, socket.AF_INET6}
        }
        return sorted(addresses, key=lambda item: (item.version, int(item)))


def resolve_target(target: str) -> list[str]:
    addresses = resolved_addresses(target)
    if not addresses:
        raise ValueError("Target did not resolve to an IP address")
    return [str(address) for address in addresses]


def run_command(command: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=180,
            shell=False,
        )
        return {
            "status": "completed" if result.returncode == 0 else "failed",
            "command": " ".join(shlex.quote(value) for value in command),
            "returncode": result.returncode,
            "raw_output": result.stdout + result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "command": " ".join(shlex.quote(value) for value in command),
            "error": "command timeout", "raw_output": "",
        }
    except Exception as exc:
        return {
            "status": "failed",
            "command": " ".join(shlex.quote(value) for value in command),
            "error": f"{type(exc).__name__}: {exc}", "raw_output": "",
        }


def structured_result(tool: str, payload: dict[str, Any], *, success: bool = True) -> dict[str, Any]:
    payload = {"tool_name": tool, "success": success, **payload}
    return {
        "status": "completed" if success else "failed",
        "command": f"builtin:{tool}",
        "parsed_result": payload,
        "raw_output": json.dumps(payload, ensure_ascii=False, sort_keys=True),
        **({} if success else {"error": payload.get("error", "collector failed")}),
    }


def target_url(target: str, port: int | None, service: str | None = None) -> str:
    selected_port = port or 80
    service_name = (service or "").lower()
    use_tls = selected_port in {443, 8443} or any(
        value in service_name for value in ("https", "ssl", "tls")
    )
    return f'{"https" if use_tls else "http"}://{target}:{selected_port}'


def run_nmap(target: str) -> dict[str, Any]:
    return run_command(["nmap", "-sV", target])


def run_httpx(target: str, port: int | None, service: str | None) -> dict[str, Any]:
    return run_command([
        "httpx", "-u", target_url(target, port, service), "-json", "-title",
        "-tech-detect", "-status-code", "-follow-redirects",
    ])


def run_nuclei(target: str, port: int | None, service: str | None, canonical_url: str | None = None) -> dict[str, Any]:
    return run_command([
        "nuclei", "-u", canonical_url or target_url(target, port, service), "-severity",
        "critical,high", "-rl", "5", "-timeout", "5", "-retries", "0", "-no-color",
    ])


def run_dirb(target: str, port: int | None, service: str | None) -> dict[str, Any]:
    return run_command(["dirb", target_url(target, port, service)])


def run_ssh_enum(target: str, port: int | None) -> dict[str, Any]:
    return run_command(["nmap", "--script", "ssh2-enum-algos", "-p", str(port or 22), target])


def run_mysql_info(target: str, port: int | None) -> dict[str, Any]:
    return run_command(["nmap", "--script", "mysql-info", "-p", str(port or 3306), target])


def run_tls_certificate(target: str, port: int | None) -> dict[str, Any]:
    selected_port = port or 443
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, selected_port), timeout=10) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=target) as tls_socket:
                der_certificate = tls_socket.getpeercert(binary_form=True)
                cipher = tls_socket.cipher()
                return structured_result("tls_certificate", {
                    "evidence_type": "tls_certificate", "host": target,
                    "port": selected_port, "service": "tls",
                    "tls_version": tls_socket.version(),
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "alpn_protocol": tls_socket.selected_alpn_protocol(),
                    "certificate_present": bool(der_certificate),
                    "certificate_sha256": hashlib.sha256(der_certificate).hexdigest()
                    if der_certificate else None,
                    "certificate_validation": "not_performed",
                    "findings": [], "finding_count": 0,
                })
    except (OSError, ssl.SSLError) as exc:
        return structured_result("tls_certificate", {
            "evidence_type": "tls_certificate", "host": target,
            "port": selected_port, "service": "tls",
            "error": f"{type(exc).__name__}: {exc}",
            "findings": [], "finding_count": 0,
        }, success=False)


def run_http_security_headers(target: str, port: int | None, service: str | None,
                              canonical_url: str | None = None) -> dict[str, Any]:
    selected_port = port or 80
    url = (canonical_url or target_url(target, selected_port, service)).rstrip("/")
    use_tls = url.startswith("https://")
    kwargs: dict[str, Any] = {"host": target, "port": selected_port, "timeout": 10}
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs["context"] = context
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(**kwargs)
    else:
        connection = http.client.HTTPConnection(**kwargs)
    try:
        connection.request("HEAD", "/", headers={
            "User-Agent": "M2A-Worker/1", "Connection": "close",
        })
        response = connection.getresponse()
        headers = {name.lower(): value for name, value in response.getheaders()}
        selected_headers = {name: headers[name] for name in EVIDENCE_HEADERS if name in headers}
        missing = [name for name in SECURITY_HEADERS if name not in headers]
        findings = [
            {"type": "missing_security_header", "header": name, "status": "observed_absent"}
            for name in missing
        ]
        return structured_result("http_security_headers", {
            "evidence_type": "http_security_posture", "host": target,
            "port": selected_port, "service": "https" if use_tls else "http",
            "url": f"{url}/", "method": "HEAD", "redirect_followed": False,
            "response_body_read": False, "status_code": response.status,
            "headers": selected_headers,
            "present_security_headers": [name for name in SECURITY_HEADERS if name in headers],
            "missing_security_headers": missing,
            "findings": findings, "finding_count": len(findings),
        })
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return structured_result("http_security_headers", {
            "evidence_type": "http_security_posture", "host": target,
            "port": selected_port, "service": "https" if use_tls else "http",
            "error": f"{type(exc).__name__}: {exc}",
            "findings": [], "finding_count": 0,
        }, success=False)
    finally:
        connection.close()


def run_dns_metadata(target: str, scoped_addresses: list[str]) -> dict[str, Any]:
    reverse_name = None
    try:
        ipaddress.ip_address(target)
        reverse_name = socket.gethostbyaddr(target)[0]
    except (ValueError, OSError):
        pass
    addresses = [
        {"record_type": "AAAA" if ipaddress.ip_address(address).version == 6 else "A",
         "address": address}
        for address in scoped_addresses
    ]
    return structured_result("dns_metadata", {
        "evidence_type": "dns_metadata", "host": target, "port": None,
        "service": "dns", "canonical_name": socket.getfqdn(target),
        "reverse_name": reverse_name, "addresses": addresses,
        "findings": addresses, "finding_count": len(addresses),
    })


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok", "version": app.version,
        "allowed_tools": sorted(ALLOWED_TOOLS),
        "scope_policy": "external_network_controls",
        "scope_enforced_by_worker": False,
    }


@app.post("/execute")
def execute(req: ExecuteRequest) -> dict[str, Any]:
    if req.tool not in ALLOWED_TOOLS:
        return {"status": "rejected", "reason": "tool not allowed", "tool": req.tool}
    identity_error = validate_execution_identity(req)
    if identity_error:
        return {"status": "rejected", "reason": identity_error, "tool": req.tool}
    try:
        addresses = resolve_target(req.target)
    except (OSError, ValueError) as exc:
        return {"status": "rejected", "reason": str(exc), "tool": req.tool}
    authorized_url = (req.authorization_parameters or {}).get("canonical_url")
    handlers = {
        "nmap_service": lambda: run_nmap(req.target),
        "httpx_basic": lambda: run_httpx(req.target, req.port, req.service),
        "nuclei_safe": lambda: run_nuclei(req.target, req.port, req.service, authorized_url),
        "dirb_safe": lambda: run_dirb(req.target, req.port, req.service),
        "ssh-enum": lambda: run_ssh_enum(req.target, req.port),
        "mysql-info": lambda: run_mysql_info(req.target, req.port),
        "tls_certificate": lambda: run_tls_certificate(req.target, req.port),
        "http_security_headers": lambda: run_http_security_headers(req.target, req.port, req.service, authorized_url),
        "dns_metadata": lambda: run_dns_metadata(req.target, addresses),
    }
    return handlers[req.tool]()

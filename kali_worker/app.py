from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import logging
import os
import shlex
import socket
import ssl
import subprocess
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict
from app.action_contracts import (
    ACTION_IDENTITIES, ACTION_BY_TOOL, ACTION_TEMPLATES, canonical_action_parameters, PROTECTED_ACTION_TOOLS,
    LAB_TARGET, LAB_PORT, HOME_LAB_EXPLORATORY, HOME_NUCLEI_TEMPLATE_PATH,
    HOME_NUCLEI_TEMPLATE_SHA256,
    HOME_ADVANCED_ACTIONS,
    nuclei_fixed_argv,
)
from app.target_identity import get_configured_target_identity_verifier, verify_runtime_target_identity
from kali_worker.build_info import worker_build_sha256
from kali_worker.replay_ledger import ReplayLedgerError, claim_authorization_once

app = FastAPI(title="M2A Kali Worker", version="evidence-tools-v1")
_authorized_argv: ContextVar[list[str] | None] = ContextVar("authorized_argv", default=None)
_execution_context: ContextVar[dict[str, Any] | None] = ContextVar("execution_context", default=None)
logger = logging.getLogger("kali_worker.execution")
WORKER_BUILD_SHA256 = worker_build_sha256()

ALLOWED_TOOLS = {
    "nmap_service", "httpx_basic", "nuclei_safe", "dirb_safe",
    "ssh-enum", "mysql-info", "tls_certificate",
    "http_security_headers", "dns_metadata",
}
# This action is visible only through the dedicated GADE experiment profile.
# It is deliberately excluded from the shared Worker profile's allowlist.
GADE_EXPERIMENT_ONLY_TOOLS = {"lab_valid_account_access", "lab_fixed_python_execution", "lab_synthetic_role_lease"}
if HOME_LAB_EXPLORATORY:
    GADE_EXPERIMENT_ONLY_TOOLS.update(HOME_ADVANCED_ACTIONS)
L2_LAB_TARGET = LAB_TARGET
L2_LAB_PORT = LAB_PORT
L2_LOGIN_PATH = "/lab/auth/login"
L2_PROTECTED_PATH = "/lab/protected"
L2_RESOURCE = "lab-only-protected-resource"
L3_EXECUTE_PATH = "/lab/execute"
L3_SCRIPT_ID = "gade-controlled-python-execution-v1"
L3_SCRIPT_SHA256 = "b6d8391432ad8f0f993a51c2c35e13d86354f3d0220c3e1c71d69e82a5f164bb"
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
    task_id: int | None = None
    authorization_id: int | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    template_id: str | None = None
    expected_worker_build_sha256: str | None = None
    target_identity_binding: dict[str, Any] | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _log_execution_event(event: str, **details: Any) -> None:
    context = _execution_context.get() or {}
    logger.info(json.dumps({"event": event, "timestamp_utc": _utc_now(),
                            **context, **details}, sort_keys=True, default=str))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


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


def worker_scope_configuration() -> tuple[bool, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Return the optional worker-side CIDR guard; isolated profiles fail closed."""
    profile = os.environ.get("KALI_WORKER_PROFILE", "shared").strip().lower()
    enabled = os.environ.get("KALI_WORKER_ENFORCE_TARGET_SCOPE", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }
    raw_scopes = os.environ.get("KALI_WORKER_ALLOWED_SCOPES", "")
    scopes = [ipaddress.ip_network(item.strip(), strict=False)
              for item in raw_scopes.split(",") if item.strip()]
    if profile == "gade-experiment" and (not enabled or not scopes):
        raise RuntimeError("isolated GADE Worker requires enabled, non-empty CIDR scope")
    if enabled and not scopes:
        raise RuntimeError("Worker target scope is enabled but no CIDRs are configured")
    return enabled, scopes


def effective_allowed_tools() -> set[str]:
    """The experiment profile exposes only tools with formal GADE Action Contracts."""
    if os.environ.get("KALI_WORKER_PROFILE", "shared").strip().lower() == "gade-experiment":
        available = (ALLOWED_TOOLS | GADE_EXPERIMENT_ONLY_TOOLS) & PROTECTED_ACTION_TOOLS
        if not nuclei_action_state()[0]:
            available = available - {"nuclei_safe"}
        if not (HOME_LAB_EXPLORATORY and os.environ.get("GADE_L4_SYNTHETIC_ENABLED") == "1"):
            available.discard("lab_synthetic_role_lease")
        if not (HOME_LAB_EXPLORATORY and os.environ.get("GADE_ADVANCED_SYNTHETIC_ENABLED") == "1"):
            available.difference_update(HOME_ADVANCED_ACTIONS)
        return available
    return ALLOWED_TOOLS


def nuclei_action_state() -> tuple[bool, str | None]:
    """Fail closed for the isolated Worker until a non-empty approved bundle is installed."""
    if os.environ.get("KALI_WORKER_PROFILE", "shared").strip().lower() != "gade-experiment":
        return True, None
    if os.environ.get("GADE_NUCLEI_ACTION_ENABLED", "false").strip().lower() not in {"1", "true", "yes", "on"}:
        return False, "nuclei.safe_scan.v1 unavailable: no approved template bundle is installed"

    manifest_value = os.environ.get("GADE_NUCLEI_TEMPLATE_MANIFEST", "/opt/gade-build/approved-nuclei-templates.json")
    templates_root = Path(os.environ.get("GADE_NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates"))
    if HOME_LAB_EXPLORATORY and templates_root.resolve() != Path(HOME_NUCLEI_TEMPLATE_PATH).parent:
        return False, "nuclei.safe_scan.v1 unavailable: home template directory differs from Action Contract"
    manifest_path = Path(manifest_value)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest.get("templates")
        if manifest.get("approval_status") != "APPROVED" or not isinstance(entries, list) or not entries:
            return False, "nuclei.safe_scan.v1 unavailable: approved template manifest is missing or empty"
        if (manifest.get("severity_selector") != "critical,high"
                or manifest.get("selection_mode") != "complete-severity-selector"
                or manifest.get("runtime_loaded_count") != len(entries)):
            return False, "nuclei.safe_scan.v1 unavailable: approved manifest does not preserve the complete critical,high selector"
        expected: set[str] = set()
        for entry in entries:
            relative = Path(str(entry["path"]))
            if str(entry.get("severity", "")).lower() not in {"critical", "high"}:
                return False, "nuclei.safe_scan.v1 unavailable: template severity is outside the fixed critical,high selector"
            if relative.is_absolute() or ".." in relative.parts:
                return False, "nuclei.safe_scan.v1 unavailable: unsafe template manifest path"
            template_path = (templates_root / relative).resolve()
            if templates_root.resolve() not in template_path.parents or not template_path.is_file():
                return False, "nuclei.safe_scan.v1 unavailable: approved template file is missing"
            if hashlib.sha256(template_path.read_bytes()).hexdigest() != str(entry.get("sha256", "")).lower():
                return False, "nuclei.safe_scan.v1 unavailable: approved template hash mismatch"
            if HOME_LAB_EXPLORATORY and str(entry.get("sha256", "")).lower() != HOME_NUCLEI_TEMPLATE_SHA256:
                return False, "nuclei.safe_scan.v1 unavailable: template hash differs from Action Contract"
            expected.add(relative.as_posix())
        actual = {path.relative_to(templates_root).as_posix() for path in templates_root.rglob("*")
                  if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}}
        if actual != expected:
            return False, "nuclei.safe_scan.v1 unavailable: installed template set differs from approved manifest"
        if HOME_LAB_EXPLORATORY and expected != {Path(HOME_NUCLEI_TEMPLATE_PATH).name}:
            return False, "nuclei.safe_scan.v1 unavailable: home template differs from Action Contract"
        return True, None
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False, "nuclei.safe_scan.v1 unavailable: approved template manifest cannot be verified"


def validate_worker_target_scope(addresses: list[str]) -> None:
    enabled, scopes = worker_scope_configuration()
    if not enabled:
        return
    parsed = [ipaddress.ip_address(address) for address in addresses]
    if not parsed or any(not any(address in network for network in scopes) for address in parsed):
        raise ValueError("target outside allowed Worker scope")


def validate_worker_target_literal(target: str) -> None:
    """Prevent an isolated Worker from sending hostnames to an external resolver."""
    if os.environ.get("KALI_WORKER_PROFILE", "shared").strip().lower() != "gade-experiment":
        return
    try:
        ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ValueError("isolated profile accepts IP literals only") from exc


def run_command(command: list[str]) -> dict[str, Any]:
    expected = _authorized_argv.get()
    if expected is not None and command != expected:
        _log_execution_event("process_rejected", reason="actual argv differs from authorization")
        return {"status": "rejected", "error": "actual argv differs from authorization",
                "execution_argv": list(command), "raw_output": "", "subprocess_started": False}
    process_started_at = None
    process_completed_at = None
    process = None
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            shell=False,
        )
        process_started_at = _utc_now()
        _log_execution_event("process_started", pid=process.pid,
                             argv_sha256=_sha256_text(json.dumps(command, separators=(",", ":"))),
                             process_started_at_utc=process_started_at)
        stdout, stderr = process.communicate(timeout=180)
        process_completed_at = _utc_now()
        combined = stdout + stderr
        _log_execution_event("process_completed", pid=process.pid, exit_code=process.returncode,
                             process_completed_at_utc=process_completed_at,
                             stdout_sha256=_sha256_text(stdout),
                             stderr_sha256=_sha256_text(stderr),
                             output_sha256=_sha256_text(combined))
        return {
            "status": "completed" if process.returncode == 0 else "failed",
            "command": " ".join(shlex.quote(value) for value in command),
            "returncode": process.returncode,
            "raw_output": combined,
            "execution_argv": list(command), "subprocess_started": True, "process_pid": process.pid,
            "process_started_at_utc": process_started_at,
            "process_completed_at_utc": process_completed_at,
            "stdout_sha256": _sha256_text(stdout),
            "stderr_sha256": _sha256_text(stderr),
            "output_sha256": _sha256_text(combined),
        }
    except subprocess.TimeoutExpired as exc:
        if process is not None:
            process.kill()
            stdout, stderr = process.communicate()
        else:
            stdout, stderr = "", ""
        process_completed_at = _utc_now()
        _log_execution_event("process_timed_out", pid=process.pid if process else None,
                             process_started_at_utc=process_started_at,
                             process_completed_at_utc=process_completed_at,
                             stdout_sha256=_sha256_text(stdout), stderr_sha256=_sha256_text(stderr))
        return {
            "status": "failed",
            "command": " ".join(shlex.quote(value) for value in command),
            "error": "command timeout", "raw_output": "",
            "execution_argv": list(command), "subprocess_started": process is not None,
            "process_pid": process.pid if process else None,
            "process_started_at_utc": process_started_at,
            "process_completed_at_utc": process_completed_at,
            "stdout_sha256": _sha256_text(stdout),
            "stderr_sha256": _sha256_text(stderr),
            "output_sha256": _sha256_text(stdout + stderr),
        }
    except Exception as exc:
        if process is not None and process.poll() is None:
            process.kill()
            stdout, stderr = process.communicate()
        else:
            stdout, stderr = "", ""
        process_completed_at = _utc_now() if process is not None else None
        _log_execution_event("process_error", pid=process.pid if process else None,
                             error_type=type(exc).__name__,
                             process_started_at_utc=process_started_at,
                             process_completed_at_utc=process_completed_at)
        return {
            "status": "failed",
            "command": " ".join(shlex.quote(value) for value in command),
            "error": f"{type(exc).__name__}: {exc}", "raw_output": "",
            "execution_argv": list(command), "subprocess_started": process is not None,
            "process_pid": process.pid if process else None,
            "process_started_at_utc": process_started_at,
            "process_completed_at_utc": process_completed_at,
            "stdout_sha256": _sha256_text(stdout),
            "stderr_sha256": _sha256_text(stderr),
            "output_sha256": _sha256_text(stdout + stderr),
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


def run_lab_valid_account_access(req: ExecuteRequest) -> dict[str, Any]:
    """Perform one fixed lab login and protected-resource check; never log secrets."""
    params = req.authorization_parameters or {}
    expected = canonical_action_parameters(
        action_id="lab.valid_account_access.v1", target=req.target, port=req.port,
        protocol=req.protocol, service=req.service,
    )
    if (req.tool != "lab_valid_account_access" or req.action_id != "lab.valid_account_access.v1"
            or req.target != L2_LAB_TARGET or req.port != L2_LAB_PORT or params != expected
            or params.get("login_path") != L2_LOGIN_PATH
            or params.get("protected_path") != L2_PROTECTED_PATH):
        return structured_result(req.tool, {"error": "fixed L2 Lab contract mismatch"}, success=False)

    username = os.environ.get("GADE_L2_TEST_USERNAME", "")
    password = os.environ.get("GADE_L2_TEST_PASSWORD", "")
    if not username or len(password) < 24:
        _log_execution_event("l2_handler_unavailable", reason="worker-local test credentials missing")
        return structured_result(req.tool, {"error": "worker-local test credentials unavailable"}, success=False)

    case_id = req.correlation_id or ""
    if not case_id or len(case_id) > 96 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-" for ch in case_id):
        return structured_result(req.tool, {"error": "invalid experiment correlation id"}, success=False)

    connection = http.client.HTTPConnection(L2_LAB_TARGET, L2_LAB_PORT, timeout=8)
    stage = "login"
    token_value: str | None = None
    try:
        login_body = json.dumps({"username": username, "password": password}, separators=(",", ":"))
        headers = {"Content-Type": "application/json", "X-Request-ID": req.request_id or "",
                   "X-Test-Case-ID": case_id, "Connection": "close"}
        _log_execution_event("l2_login_request_started", endpoint=L2_LOGIN_PATH,
                             request_id=req.request_id, test_case_id=case_id)
        connection.request("POST", L2_LOGIN_PATH, body=login_body, headers=headers)
        login_response = connection.getresponse()
        login_status = login_response.status
        login_raw = login_response.read(8192)
        if login_status != 200:
            _log_execution_event("l2_login_rejected", status_code=login_status,
                                 request_id=req.request_id, test_case_id=case_id)
            return structured_result(req.tool, {"error": "lab login was rejected",
                "login_http_status": login_status, "test_case_id": case_id}, success=False)
        try:
            login_data = json.loads(login_raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return structured_result(req.tool, {"error": "lab login returned invalid JSON",
                "login_http_status": login_status, "test_case_id": case_id}, success=False)
        token_value = login_data.get("session_token") if isinstance(login_data, dict) else None
        ttl = login_data.get("expires_in") if isinstance(login_data, dict) else None
        if (not isinstance(token_value, str) or len(token_value) < 32 or ttl != 60
                or login_data.get("test_case_id") != case_id):
            return structured_result(req.tool, {"error": "lab login response contract mismatch",
                "login_http_status": login_status, "test_case_id": case_id}, success=False)
        token_fingerprint = hashlib.sha256(token_value.encode("utf-8")).hexdigest()[:12]

        stage = "protected_resource"
        connection.close()


        connection = http.client.HTTPConnection(L2_LAB_TARGET, L2_LAB_PORT, timeout=8)
        protected_headers = {"Authorization": f"Bearer {token_value}",
                             "X-Request-ID": req.request_id or "",
                             "X-Test-Case-ID": case_id, "Connection": "close"}
        _log_execution_event("l2_protected_request_started", endpoint=L2_PROTECTED_PATH,
                             request_id=req.request_id, test_case_id=case_id,
                             session_fingerprint=token_fingerprint)
        connection.request("GET", L2_PROTECTED_PATH, headers=protected_headers)
        protected_response = connection.getresponse()
        protected_status = protected_response.status
        protected_raw = protected_response.read(8192)
        try:
            protected_data = json.loads(protected_raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            protected_data = None
        access_ok = (protected_status == 200 and isinstance(protected_data, dict)
                     and protected_data.get("resource") == L2_RESOURCE
                     and protected_data.get("scenario") == "T1078-test-account"
                     and protected_data.get("access") == "granted"
                     and protected_data.get("test_case_id") == case_id)
        if not access_ok:
            _log_execution_event("l2_protected_access_failed", status_code=protected_status,
                                 request_id=req.request_id, test_case_id=case_id,
                                 session_fingerprint=token_fingerprint)
            return structured_result(req.tool, {"error": "protected resource verification failed",
                "login_http_status": login_status, "protected_http_status": protected_status,
                "session_ttl_seconds": ttl, "session_fingerprint": token_fingerprint,
                "test_case_id": case_id}, success=False)

        safe_result = {"success": True, "login_http_status": login_status,
            "protected_http_status": protected_status, "session_ttl_seconds": ttl,
            "session_fingerprint": token_fingerprint, "protected_resource": L2_RESOURCE,
            "scenario": "T1078-test-account", "test_case_id": case_id}
        _log_execution_event("l2_protected_access_verified", status_code=protected_status,
                             request_id=req.request_id, test_case_id=case_id,
                             session_fingerprint=token_fingerprint)
        return structured_result(req.tool, safe_result)
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        _log_execution_event("l2_http_failure", stage=stage, error_type=type(exc).__name__,
                             request_id=req.request_id, test_case_id=case_id)
        return structured_result(req.tool, {"error": "fixed Lab HTTP exchange failed",
            "failed_stage": stage, "error_type": type(exc).__name__, "test_case_id": case_id}, success=False)
    finally:
        token_value = None
        connection.close()
def run_lab_fixed_python_execution(req: ExecuteRequest) -> dict[str, Any]:
    """Trigger only the target's pre-installed, session-gated L3 emulation."""
    action_id = "lab.fixed_python_execution.v1"
    params = req.authorization_parameters or {}
    try:
        expected = canonical_action_parameters(action_id=action_id, target=req.target,
            port=req.port, protocol=req.protocol, service=req.service)
    except ValueError:
        expected = None
    if (req.tool != "lab_fixed_python_execution" or req.action_id != action_id
            or req.target != L2_LAB_TARGET or req.port != L2_LAB_PORT or params != expected
            or params.get("execute_path") != L3_EXECUTE_PATH
            or params.get("script_id") != L3_SCRIPT_ID or params.get("script_sha256") != L3_SCRIPT_SHA256):
        return structured_result(req.tool, {"error": "fixed L3 Lab contract mismatch"}, success=False)
    username = os.environ.get("GADE_L2_TEST_USERNAME", "")
    password = os.environ.get("GADE_L2_TEST_PASSWORD", "")
    if not username or len(password) < 24:
        _log_execution_event("l3_handler_unavailable", reason="worker-local test credentials missing")
        return structured_result(req.tool, {"error": "worker-local test credentials unavailable"}, success=False)
    case_id = req.correlation_id or ""
    pieces = case_id.split("-")
    run_id = pieces[-1] if len(pieces) >= 4 and pieces[0:2] == ["GADE", "L3"] else ""
    if (not run_id or len(run_id) != 12 or any(ch not in "0123456789abcdef" for ch in run_id)
            or len(case_id) > 96 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-" for ch in case_id)):
        return structured_result(req.tool, {"error": "invalid L3 run/correlation identity"}, success=False)
    connection = http.client.HTTPConnection(L2_LAB_TARGET, L2_LAB_PORT, timeout=8)
    stage = "login"
    token_value: str | None = None
    try:
        login_body = json.dumps({"username": username, "password": password}, separators=(",", ":"))
        headers = {"Content-Type": "application/json", "X-Request-ID": req.request_id or "",
                   "X-Test-Case-ID": case_id, "X-Run-ID": run_id, "Connection": "close"}
        _log_execution_event("l3_login_request_started", endpoint=L2_LOGIN_PATH,
                             request_id=req.request_id, test_case_id=case_id)
        connection.request("POST", L2_LOGIN_PATH, body=login_body, headers=headers)
        login_response = connection.getresponse()
        login_status = login_response.status
        login_raw = login_response.read(8192)
        if login_status != 200:
            return structured_result(req.tool, {"error": "lab login was rejected",
                "login_http_status": login_status, "test_case_id": case_id}, success=False)
        try:
            login_data = json.loads(login_raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            login_data = None
        token_value = login_data.get("session_token") if isinstance(login_data, dict) else None
        if (not isinstance(token_value, str) or len(token_value) < 32
                or login_data.get("expires_in") != 60 or login_data.get("test_case_id") != case_id):
            return structured_result(req.tool, {"error": "lab login response contract mismatch",
                "login_http_status": login_status, "test_case_id": case_id}, success=False)
        fingerprint = hashlib.sha256(token_value.encode("utf-8")).hexdigest()[:12]
        stage = "fixed_python_execution"
        connection.close()


        connection = http.client.HTTPConnection(L2_LAB_TARGET, L2_LAB_PORT, timeout=12)
        execute_headers = {"Authorization": f"Bearer {token_value}",
            "Content-Type": "application/json", "X-Request-ID": req.request_id or "",
            "X-Test-Case-ID": case_id, "X-Run-ID": run_id, "Connection": "close"}
        _log_execution_event("l3_target_execution_request_started", endpoint=L3_EXECUTE_PATH,
            request_id=req.request_id, test_case_id=case_id, script_id=L3_SCRIPT_ID,
            script_sha256=L3_SCRIPT_SHA256, session_fingerprint=fingerprint)
        connection.request("POST", L3_EXECUTE_PATH, body="{}", headers=execute_headers)
        response = connection.getresponse()
        status = response.status
        raw = response.read(8192)
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None
        success = (status == 200 and isinstance(body, dict) and body.get("status") == "completed"
            and body.get("run_id") == run_id and body.get("test_case_id") == case_id
            and body.get("request_id") == req.request_id and body.get("script_id") == L3_SCRIPT_ID
            and body.get("script_sha256") == L3_SCRIPT_SHA256 and body.get("exit_status") == 0
            and isinstance(body.get("marker_sha256"), str)
            and len(body["marker_sha256"]) == 64)
        if not success:
            _log_execution_event("l3_target_execution_failed", status_code=status,
                request_id=req.request_id, test_case_id=case_id, session_fingerprint=fingerprint)
            return structured_result(req.tool, {"error": "fixed target-side execution verification failed",
                "login_http_status": login_status, "execute_http_status": status,
                "test_case_id": case_id, "response_sha256": _sha256_text(raw.decode("utf-8", "replace"))}, success=False)
        _log_execution_event("l3_target_execution_verified", status_code=status,
            request_id=req.request_id, test_case_id=case_id, script_id=L3_SCRIPT_ID,
            marker_sha256=body["marker_sha256"], session_fingerprint=fingerprint)
        return structured_result(req.tool, {"success": True, "login_http_status": login_status,
            "execute_http_status": status, "run_id": run_id, "test_case_id": case_id,
            "script_id": L3_SCRIPT_ID, "script_sha256": L3_SCRIPT_SHA256,
            "process_exit_status": 0, "marker_sha256": body["marker_sha256"],
            "session_fingerprint": fingerprint})
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        _log_execution_event("l3_http_failure", stage=stage, error_type=type(exc).__name__,
            request_id=req.request_id, test_case_id=case_id)
        return structured_result(req.tool, {"error": "fixed L3 Lab HTTP exchange failed",
            "failed_stage": stage, "error_type": type(exc).__name__, "test_case_id": case_id}, success=False)
    finally:
        token_value = None
        connection.close()


def run_lab_synthetic_role_lease(req: ExecuteRequest) -> dict[str, Any]:
    """Create only the approved synthetic role lease and verify its fixed resource."""
    action_id = "lab.synthetic_role_lease.v1"
    try:
        expected = canonical_action_parameters(action_id=action_id, target=req.target,
            port=req.port, protocol=req.protocol, service=req.service)
    except ValueError:
        expected = None
    if (os.environ.get("GADE_L4_SYNTHETIC_ENABLED") != "1"
            or req.tool != "lab_synthetic_role_lease" or req.action_id != action_id
            or req.authorization_parameters != expected):
        return structured_result(req.tool, {"error": "fixed L4 Lab contract mismatch"}, success=False)
    username = os.environ.get("GADE_L2_TEST_USERNAME", "")
    password = os.environ.get("GADE_L2_TEST_PASSWORD", "")
    case_id = req.correlation_id or ""
    pieces = case_id.split("-")
    reviewed_case = (case_id.startswith("GADE-L3-MULTI-A-R")
                     or case_id.startswith("GADE-L4-ENGINEERING-"))
    run_id = pieces[-1] if reviewed_case else ""
    if (not username or len(password) < 24 or not run_id or len(run_id) != 12
            or any(ch not in "0123456789abcdef" for ch in run_id)
            or len(case_id) > 96 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-" for ch in case_id)):
        return structured_result(req.tool, {"error": "L4 credentials or correlation identity unavailable"}, success=False)
    headers = {"X-Request-ID": req.request_id or "", "X-Test-Case-ID": case_id,
               "X-Run-ID": run_id, "Connection": "close"}
    stage = "login"
    connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=8)
    token_value: str | None = None
    try:
        connection.request("POST", "/lab/auth/login",
            body=json.dumps({"username": username, "password": password}, separators=(",", ":")),
            headers={**headers, "Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read(8192))
        if (response.status != 200 or not isinstance(body, dict)
                or body.get("expires_in") != 60 or body.get("test_case_id") != case_id
                or not isinstance(body.get("session_token"), str)
                or len(body["session_token"]) < 32):
            raise ValueError("fixed test-account login failed")
        token_value = body["session_token"]
        connection.close()


        stage = "role_lease"
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=8)
        connection.request("POST", "/lab/l4/role-lease", body="{}",
            headers={**headers, "Content-Type": "application/json",
                     "Authorization": f"Bearer {token_value}"})
        response = connection.getresponse()
        lease = json.loads(response.read(8192))
        if (response.status != 200 or not isinstance(lease, dict)
                or lease.get("outcome") != "completed" or lease.get("run_id") != run_id
                or lease.get("test_case_id") != case_id or lease.get("request_id") != req.request_id
                or lease.get("role") != "synthetic-lab-operator"
                or lease.get("ttl_seconds") != 300 or lease.get("simulation") is not True
                or not isinstance(lease.get("state_sha256"), str)
                or len(lease["state_sha256"]) != 64):
            raise ValueError("synthetic role lease proof mismatch")
        connection.close()
        stage = "protected_resource"
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=8)
        connection.request("GET", "/lab/l4/protected",
            headers={**headers, "Authorization": f"Bearer {token_value}"})
        response = connection.getresponse()
        resource = json.loads(response.read(8192))
        if (response.status != 200 or not isinstance(resource, dict)
                or resource.get("resource") != "lab-only-l4-role-resource"
                or resource.get("role") != "synthetic-lab-operator"
                or resource.get("simulation") is not True):
            raise ValueError("synthetic role did not change protected-resource access")
        return structured_result(req.tool, {"success": True, "run_id": run_id,
            "test_case_id": case_id, "request_id": req.request_id,
            "lease_http_status": 200, "protected_http_status": 200,
            "role": "synthetic-lab-operator", "lease_ttl_seconds": 300,
            "state_sha256": lease["state_sha256"], "simulation": True})
    except (OSError, http.client.HTTPException, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        _log_execution_event("l4_fixed_action_failed", stage=stage,
                             error_type=type(exc).__name__, request_id=req.request_id,
                             test_case_id=case_id)
        return structured_result(req.tool, {"error": "fixed L4 Lab exchange failed",
            "failed_stage": stage, "error_type": type(exc).__name__, "test_case_id": case_id}, success=False)
    finally:
        token_value = None
        connection.close()

def run_lab_advanced_synthetic(req: ExecuteRequest) -> dict[str, Any]:
    """Execute exactly one home-only synthetic transition, never arbitrary paths or payloads."""
    spec = HOME_ADVANCED_ACTIONS.get(req.tool)
    if not (HOME_LAB_EXPLORATORY and os.environ.get("GADE_ADVANCED_SYNTHETIC_ENABLED") == "1"
            and spec is not None and req.action_id == spec[0]):
        return structured_result(req.tool, {"error": "advanced synthetic action unavailable"}, success=False)
    try:
        expected = canonical_action_parameters(action_id=spec[0], target=req.target,
            port=req.port, protocol=req.protocol, service=req.service)
    except ValueError:
        expected = None
    if req.authorization_parameters != expected:
        return structured_result(req.tool, {"error": "advanced synthetic contract mismatch"}, success=False)
    case_id = req.correlation_id or ""
    run_id = case_id.split("-")[-1] if case_id.startswith("GADE-L3-MULTI-A-R") else ""
    username = os.environ.get("GADE_L2_TEST_USERNAME", "")
    password = os.environ.get("GADE_L2_TEST_PASSWORD", "")
    if (not run_id or len(run_id) != 12 or any(ch not in "0123456789abcdef" for ch in run_id)
            or len(case_id) > 96 or not username or len(password) < 24):
        return structured_result(req.tool, {"error": "advanced synthetic identity or test account unavailable"}, success=False)
    headers = {"X-Request-ID": req.request_id or "", "X-Test-Case-ID": case_id,
               "X-Run-ID": run_id, "Connection": "close"}
    connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=8)
    token_value: str | None = None
    stage = "login"
    try:
        connection.request("POST", "/lab/auth/login",
            body=json.dumps({"username": username, "password": password}, separators=(",", ":")),
            headers={**headers, "Content-Type": "application/json"})
        response = connection.getresponse()
        login = json.loads(response.read(8192))
        if (response.status != 200 or not isinstance(login, dict)
                or login.get("expires_in") != 60 or login.get("test_case_id") != case_id
                or not isinstance(login.get("session_token"), str)
                or len(login["session_token"]) < 32):
            raise ValueError("fixed test-account login failed")
        token_value = login["session_token"]
        connection.close()
        stage = "advanced_action"
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=8)
        connection.request("POST", expected["action_path"], body="{}",
            headers={**headers, "Content-Type": "application/json",
                     "Authorization": f"Bearer {token_value}"})
        response = connection.getresponse()
        effect = json.loads(response.read(8192))
        state_sha = effect.get("state_sha256") if isinstance(effect, dict) else None
        if (response.status != 200 or not isinstance(effect, dict)
                or effect.get("outcome") != "completed" or effect.get("action") != spec[2]
                or effect.get("run_id") != run_id or effect.get("test_case_id") != case_id
                or effect.get("request_id") != req.request_id or effect.get("simulation") is not True
                or not isinstance(state_sha, str) or len(state_sha) != 64
                or any(ch not in "0123456789abcdef" for ch in state_sha)):
            raise ValueError("advanced synthetic state proof mismatch")
        safe_effect = effect.get("effect")
        if not isinstance(safe_effect, dict) or set(safe_effect) - {
            "canary_id", "control_simulation", "real_security_controls_changed",
            "node_ids", "source_node", "destination_node", "record_ids",
            "message", "ack", "receiver_id", "payload_sha256", "external_network_used",
            "impact_mode", "real_service_interrupted"}:
            raise ValueError("advanced synthetic effect contains unreviewed fields")
        return structured_result(req.tool, {"success": True, "run_id": run_id,
            "test_case_id": case_id, "request_id": req.request_id,
            "action": spec[2], "action_http_status": 200,
            "state_sha256": state_sha, "effect": safe_effect, "simulation": True})
    except (OSError, http.client.HTTPException, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        _log_execution_event("advanced_synthetic_failed", stage=stage,
                             action_id=req.action_id, error_type=type(exc).__name__)
        return structured_result(req.tool, {"error": "fixed advanced synthetic exchange failed",
            "failed_stage": stage, "error_type": type(exc).__name__}, success=False)
    finally:
        token_value = None
        connection.close()

def target_url(target: str, port: int | None, service: str | None = None) -> str:
    selected_port = port or 80
    service_name = (service or "").lower()
    use_tls = selected_port in {443, 8443} or any(
        value in service_name for value in ("https", "ssl", "tls")
    )
    return f'{"https" if use_tls else "http"}://{target}:{selected_port}'


def run_nmap(target: str) -> dict[str, Any]:
    return run_command(["nmap", "-sV", target])


def run_httpx(target: str, port: int | None, service: str | None,
              canonical_url: str | None = None) -> dict[str, Any]:
    return run_command([
        "httpx", "-u", canonical_url or target_url(target, port, service), "-json", "-title",
        "-tech-detect", "-status-code",
    ])


def run_nuclei(target: str, port: int | None, service: str | None, canonical_url: str | None = None) -> dict[str, Any]:
    available, reason = nuclei_action_state()
    if not available:
        raise RuntimeError(reason or "nuclei.safe_scan.v1 unavailable")
    return run_command(nuclei_fixed_argv(canonical_url or target_url(target, port, service)))


def run_dirb(target: str, port: int | None, service: str | None) -> dict[str, Any]:
    return run_command(["dirb", target_url(target, port, service)])


def run_ssh_enum(target: str, port: int | None) -> dict[str, Any]:
    return run_command(["nmap", "--script", "ssh2-enum-algos", "-p", str(port or 22), target])


def run_mysql_info(target: str, port: int | None) -> dict[str, Any]:
    return run_command(["nmap", "--script", "mysql-info", "-p", str(port or 3306), target])


def run_tls_certificate(target: str, port: int | None, sni: str | None = None) -> dict[str, Any]:
    selected_port = port or 443
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, selected_port), timeout=10) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=sni or target) as tls_socket:
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
    scope_enabled, scopes = worker_scope_configuration()
    nuclei_available, nuclei_reason = nuclei_action_state()
    return {
        "status": "ok", "version": app.version,
        "build_sha256": WORKER_BUILD_SHA256,
        "registered_tools": sorted(((ALLOWED_TOOLS | GADE_EXPERIMENT_ONLY_TOOLS)
                                     if os.environ.get("KALI_WORKER_PROFILE", "shared").strip().lower() == "gade-experiment"
                                     else ALLOWED_TOOLS) & PROTECTED_ACTION_TOOLS),
        "allowed_tools": sorted(effective_allowed_tools()),
        "unavailable_actions": (([] if nuclei_available else [{"action_id": "nuclei.safe_scan.v1", "reason": nuclei_reason}])
            + ([] if "lab_synthetic_role_lease" in effective_allowed_tools() else
               [{"action_id": "lab.synthetic_role_lease.v1", "reason": "home L4 action disabled by default"}])
            + ([] if os.environ.get("GADE_ADVANCED_SYNTHETIC_ENABLED") == "1" else
               [{"action_id": action, "reason": "home advanced synthetic action disabled by default"}
                for action, _depth, _path in HOME_ADVANCED_ACTIONS.values()])),
        "scope_policy": "worker_enforced_cidr" if scope_enabled else "external_network_controls",
        "scope_enforced_by_worker": scope_enabled,
        "allowed_scopes": [str(scope) for scope in scopes],
    }


@app.post("/execute")
def execute(req: ExecuteRequest) -> dict[str, Any]:
    request_received_at = _utc_now()
    request_context = {"request_id": req.request_id, "tool_task_id": req.task_id,
                       "correlation_id": req.correlation_id,
                       "authorization_id": req.authorization_id, "action_id": req.action_id,
                       "template_id": req.template_id,
                       "expected_worker_build_sha256": req.expected_worker_build_sha256,
                       "target": req.target, "port": req.port}
    _log_execution_event("request_received", **request_context)

    def reject(reason: str) -> dict[str, Any]:
        _log_execution_event("request_rejected", reason=reason)
        return {"status": "rejected", "reason": reason, "tool": req.tool}

    if req.tool == "nuclei_safe":
        nuclei_available, nuclei_reason = nuclei_action_state()
        if not nuclei_available:
            _log_execution_event("action_unavailable", action_id="nuclei.safe_scan.v1", reason=nuclei_reason)
            return {"status": "unavailable", "reason": nuclei_reason, "tool": req.tool,
                    "action_id": "nuclei.safe_scan.v1"}

    if req.tool not in effective_allowed_tools():
        return reject("tool not allowed")
    if os.environ.get("KALI_WORKER_PROFILE", "shared").strip().lower() == "gade-experiment":
        if (req.action_id is None or req.authorization_id is None or req.task_id is None
                or not req.request_id or not req.correlation_id or not req.template_id
                or not req.expected_worker_build_sha256):
            return reject("isolated profile requires governed execution metadata")
    try:
        identity_error = validate_execution_identity(req)
    except (ValueError, TypeError) as exc:
        identity_error = str(exc)
    if identity_error:
        return reject(identity_error)
    if req.authorization_id is not None:
        if (req.action_id is None or req.task_id is None or not req.request_id
                or not req.template_id or not req.expected_worker_build_sha256):
            return reject("governed request correlation fields missing")
        try:
            UUID(req.request_id)
        except (ValueError, TypeError, AttributeError):
            return reject("request_id must be a UUID")
        if req.template_id != ACTION_TEMPLATES.get(req.action_id):
            return reject("template_id does not match action contract")
        if req.expected_worker_build_sha256 != WORKER_BUILD_SHA256:
            return reject("Worker build hash does not match requested repository build")
    elif req.action_id is not None and req.template_id is not None:
        if req.template_id != ACTION_TEMPLATES.get(req.action_id):
            return reject("template_id does not match action contract")
    try:
        validate_worker_target_literal(req.target)
        addresses = resolve_target(req.target)
        validate_worker_target_scope(addresses)
    except (OSError, ValueError) as exc:
        return reject(str(exc))
    except RuntimeError as exc:
        return reject(str(exc))
    if req.action_id == "lab.synthetic_node_discovery.v1":
        binding = req.target_identity_binding
        scope = binding.get("scope") if isinstance(binding, dict) else None
        target_record_id = binding.get("target_id") if isinstance(binding, dict) else None
        runtime_target = SimpleNamespace(id=target_record_id, target=req.target, scope=scope)
        identity_reason = verify_runtime_target_identity(
            binding=binding, target=runtime_target, action_id=req.action_id,
            execution_identity=req.execution_identity or "",
            parameters_hash=req.authorization_parameters_hash or "",
            authorization_id=req.authorization_id,
            verifier=get_configured_target_identity_verifier(),
        )
        _log_execution_event("target_identity_check",
                             outcome="DENY" if identity_reason else "ALLOW",
                             reason_code=identity_reason or "TARGET_IDENTITY_MATCH",
                             binding_sha256=(binding or {}).get("binding_sha256") if isinstance(binding, dict) else None)
        if identity_reason:
            return reject(identity_reason)
    replay_claim = "NOT_GOVERNED"
    if req.authorization_id is not None:
        try:
            claim_authorization_once(
                os.environ.get("KALI_WORKER_REPLAY_DB_PATH"),
                authorization_id=req.authorization_id,
                task_id=req.task_id,
                request_id=req.request_id or "",
                request_hash=parameters_hash(req.model_dump()),
            )
        except ReplayLedgerError as exc:
            _log_execution_event("authorization_replay_claim", outcome="DENY",
                                 reason_code=exc.reason_code)
            return reject(exc.reason_code)
        replay_claim = "PERSISTED_SINGLE_USE"
        _log_execution_event("authorization_replay_claim", outcome="ALLOW",
                             reason_code="PERSISTED_SINGLE_USE")
    authorized_url = (req.authorization_parameters or {}).get("canonical_url")
    authorized_sni = (req.authorization_parameters or {}).get("sni")
    handlers = {
        "lab_synthetic_role_lease": lambda: run_lab_synthetic_role_lease(req),
        **{tool: (lambda: run_lab_advanced_synthetic(req)) for tool in HOME_ADVANCED_ACTIONS},
        "lab_valid_account_access": lambda: run_lab_valid_account_access(req),
        "lab_fixed_python_execution": lambda: run_lab_fixed_python_execution(req),
        "nmap_service": lambda: run_nmap(req.target),
        "httpx_basic": lambda: run_httpx(req.target, req.port, req.service, authorized_url),
        "nuclei_safe": lambda: run_nuclei(req.target, req.port, req.service, authorized_url),
        "dirb_safe": lambda: run_dirb(req.target, req.port, req.service),
        "ssh-enum": lambda: run_ssh_enum(req.target, req.port),
        "mysql-info": lambda: run_mysql_info(req.target, req.port),
        "tls_certificate": lambda: run_tls_certificate(req.target, req.port, authorized_sni),
        "http_security_headers": lambda: run_http_security_headers(req.target, req.port, req.service, authorized_url),
        "dns_metadata": lambda: run_dns_metadata(req.target, addresses),
    }
    token = _authorized_argv.set((req.authorization_parameters or {}).get("argv"))
    request_token = _execution_context.set(request_context)
    handler_started_at = _utc_now()
    _log_execution_event("handler_started", request_received_at_utc=request_received_at,
                         handler_started_at_utc=handler_started_at)
    try:
        result = handlers[req.tool]()
    except Exception as exc:
        _log_execution_event("handler_exception", error_type=type(exc).__name__)
        raise
    finally:
        _authorized_argv.reset(token)
        _execution_context.reset(request_token)
    observed = canonical_parameters(req)
    if "execution_argv" in result:
        observed["argv"] = result["execution_argv"]
    result["execution_receipt"] = {
        "request_id": req.request_id,
        "correlation_id": req.correlation_id,
        "task_id": req.task_id, "authorization_id": req.authorization_id,
        "worker_replay_claim": replay_claim,
        "template_id": req.template_id,
        "request_hash": parameters_hash(req.model_dump()),
        "executed_action": req.action_id, "executed_parameters": observed,
        "execution_identity": req.execution_identity, "handler_invoked": True,
        "subprocess_started": result.get("subprocess_started"),
        "request_received_at_utc": request_received_at,
        "handler_started_at_utc": handler_started_at,
        "handler_completed_at_utc": _utc_now(),
        "worker_build_sha256": WORKER_BUILD_SHA256,
        "process_started_at_utc": result.get("process_started_at_utc"),
        "process_completed_at_utc": result.get("process_completed_at_utc"),
        "process_pid": result.get("process_pid"),
        "process_exit_code": result.get("returncode"),
        "process_output_sha256": result.get("output_sha256", _sha256_text(result.get("raw_output", ""))),
        "execution_outcome": result.get("status", "unknown"),
        "action_success": (result.get("status") in ("completed", "success", "done")
                           and (result.get("parsed_result") or {}).get("success") is not False),
        "execution_kind": "subprocess" if "subprocess_started" in result else "builtin_handler",
        "observation": "handler invocation / actual argv; no destination attestation",
    }
    _log_execution_event("handler_completed", **request_context,
                         execution_outcome=result["execution_receipt"]["execution_outcome"],
                         action_success=result["execution_receipt"]["action_success"],
                         receipt_sha256=parameters_hash(result["execution_receipt"]))
    return result

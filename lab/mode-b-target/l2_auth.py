"""Minimal isolated valid-account/session scenario; Python standard library only."""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError
from uuid import uuid4
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

CASE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
REQUEST_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
RUN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
GADE_L2_CASE_RUN_RE = re.compile(r"^GADE-L3-[A-Za-z0-9_.-]*-([0-9a-f]{12})$")
MAX_BODY = 4096
WORKER_INGRESS_AUTH_REQUIRED = os.environ.get("GADE_WORKER_INGRESS_AUTH_REQUIRED") == "1"
WORKER_INGRESS_PROTECTED_PATHS = {
    "/lab/l4/role-lease", "/lab/l4/protected",
}
# The dedicated Worker previously showed approximately 155 seconds of clock skew.
# The proof is still single-use and request-bound; this window only avoids rejecting
# valid synthetic traffic because host and Worker clocks drift.
WORKER_INGRESS_TIMESTAMP_SKEW_SECONDS = 300
BLUE_OBSERVER_REQUIRED = os.environ.get("GADE_BLUE_OBSERVER_REQUIRED") == "1"
SEPARATE_COMPONENTS_REQUIRED = os.environ.get("GADE_SEPARATE_SYNTHETIC_SERVICES") == "1"
BLUE_OBSERVER_URL = os.environ.get("GADE_BLUE_OBSERVER_URL", "http://blue-observer:8090/ingest")
BLUE_OBSERVER_KEY = os.environ.get("GADE_BLUE_OBSERVER_KEY", "")
COMPONENT_API_KEY = os.environ.get("GADE_COMPONENT_API_KEY", "")
COMPONENT_REQUEST_TIMEOUT_SECONDS = 3.0
L7_TRANSFER_COMPONENT_BUDGET_SECONDS = 6.0
RESET_COMPONENT_BUDGET_SECONDS = 12.0
COMPONENT_URLS = {
    "node-alpha": os.environ.get("GADE_NODE_ALPHA_URL", "http://node-alpha:8091"),
    "node-beta": os.environ.get("GADE_NODE_BETA_URL", "http://node-beta:8091"),
    "receiver": os.environ.get("GADE_RECEIVER_URL", "http://receiver:8092"),
}
COMPONENT_INITIAL_STATE = {
    "node-alpha": {"node_id": "node-alpha", "opened_sessions": [], "completed_requests": []},
    "node-beta": {"node_id": "node-beta", "accepted_sessions": [], "completed_requests": []},
    "receiver": {"receiver_id": "lab-receiver-fixed", "accepted_payloads": [], "completed_requests": []},
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def worker_ingress_signature(password: bytes, method: str, path: str, run_id: str,
                             case_id: str, request_id: str, timestamp: str,
                             nonce: str) -> str:
    """Sign one fixed synthetic Worker request without exposing the account password."""
    if not password:
        raise ValueError("worker ingress credential is unavailable")
    key = hmac.new(password, b"gade-office-worker-ingress-key-v1", hashlib.sha256).digest()
    canonical = "\n".join((method, path, run_id, case_id, request_id, timestamp, nonce))
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def worker_ingress_path_is_protected(path: str) -> bool:
    return path in WORKER_INGRESS_PROTECTED_PATHS or path.startswith("/lab/advanced/")


L3_SCRIPT = Path(__file__).with_name("l3_execution_task.py")
L3_SCRIPT_ID = "gade-controlled-python-execution-v1"
L3_MARKER_NAME = "execution-marker.json"
L4_ROLE_STATE_NAME = "synthetic-role-lease.json"
L4_ROLE = "synthetic-lab-operator"
L4_LEASE_SECONDS = 300
ADVANCED_STATE_NAME = "synthetic-advanced-state.json"
ADVANCED_ACTIONS = {
    "l5-canary": "l5_canary_accessed",
    "l5-visibility": "l5_visibility_simulated",
    "l6-discovery": "l6_topology_discovered",
    "l6-session": "l6_session_established",
    "l7-collection": "l7_collection_created",
    "l7-c2": "l7_local_c2_acknowledged",
    "l7-transfer": "l7_receiver_transfer_completed",
    "l7-impact": "l7_impact_simulated",
}
ADVANCED_INITIAL = {
    "canary_accessed": False, "visibility_mode": "normal",
    "discovered_nodes": [], "node_session_active": False,
    "collected_ids": [], "c2_heartbeat_count": 0,
    "receiver_digest": None, "impact_mode": "normal",
    "completed_request_ids": [],
    "completed_actions": [],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def component_request(url: str, path: str, *, method: str, run_id: str,
                      case_id: str, request_id: str, body: dict[str, Any] | None = None,
                      observer: bool = False, timeout_seconds: float = COMPONENT_REQUEST_TIMEOUT_SECONDS,
                      deadline_monotonic: float | None = None) -> dict[str, Any]:
    data = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    headers = {"X-Run-ID": run_id, "X-Test-Case-ID": case_id, "X-Request-ID": request_id,
               "X-GADE-Component-Key": COMPONENT_API_KEY}
    if observer:
        headers["X-GADE-Observer-Key"] = BLUE_OBSERVER_KEY
    if data is not None:
        headers["Content-Type"] = "application/json"
    allowed_bases = {value.rstrip("/") for value in COMPONENT_URLS.values()}
    allowed_bases.add(BLUE_OBSERVER_URL.rsplit("/", 1)[0].rstrip("/"))
    base = url.rstrip("/")
    if base not in allowed_bases:
        raise ValueError("synthetic service URL is outside the fixed internal allowlist")
    if deadline_monotonic is not None:
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("fixed synthetic component action budget expired")
        timeout_seconds = min(timeout_seconds, remaining)
    request = urllib.request.Request(url + path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=timeout_seconds) as response:
        value = json.loads(response.read(8192))
        if not isinstance(value, dict):
            raise ValueError("synthetic component returned an invalid response")
        return value


def valid_receiver_acceptance(value: Any, expected_digest: str) -> bool:
    """Validate the complete fixed Receiver response before Target completion."""
    if not isinstance(value, dict) or set(value) != {
            "status", "receiver_id", "payload_sha256", "state_sha256", "event_id"}:
        return False
    state_sha = value.get("state_sha256")
    event_id = value.get("event_id")
    return (value.get("status") == "accepted"
            and value.get("receiver_id") == "lab-receiver-fixed"
            and value.get("payload_sha256") == expected_digest
            and isinstance(state_sha, str) and re.fullmatch(r"[0-9a-f]{64}", state_sha) is not None
            and isinstance(event_id, str) and re.fullmatch(r"[0-9a-f]{32}", event_id) is not None)


def synthetic_failure_code(exc: Exception, stage: str) -> str:
    """Return bounded diagnostic codes; exception messages may contain secrets."""
    if isinstance(exc, TimeoutError):
        return "COMPONENT_TIMEOUT"
    if isinstance(exc, json.JSONDecodeError):
        return "COMPONENT_RESPONSE_INVALID_JSON"
    if isinstance(exc, ValueError):
        return "FIXED_RESPONSE_OR_STATE_INVALID"
    if isinstance(exc, OSError):
        return "COMPONENT_UNAVAILABLE"
    if isinstance(exc, RuntimeError):
        return "FIXED_ACTION_REJECTED"
    return "FIXED_ACTION_FAILED"


class AuthState:
    def __init__(self, username: str, password: str, reset_key: str, ttl: int = 60,
                 state_dir: str | Path | None = None, enable_l4: bool = False,
                 enable_advanced: bool = False):
        if not username or len(password) < 24 or len(reset_key) < 24:
            raise ValueError("test account configuration is missing or too short")
        if not 1 <= ttl <= 600:
            raise ValueError("session TTL must be between 1 and 600 seconds")
        self.username = username
        self._password = password.encode("utf-8")
        self._reset_key = reset_key.encode("utf-8")
        self.worker_ingress_required = WORKER_INGRESS_AUTH_REQUIRED
        self.worker_ingress_nonces: dict[str, int] = {}
        self.ttl = ttl
        self.sessions: dict[str, tuple[float, str]] = {}
        self.state_dir = Path(state_dir or os.environ.get("GADE_L3_STATE_DIR", "/tmp/gade-l3"))
        self.marker_path = self.state_dir / L3_MARKER_NAME
        self.l4_state_path = self.state_dir / L4_ROLE_STATE_NAME
        self.l4_enabled = enable_l4
        self.advanced_enabled = enable_advanced
        self.advanced_state_path = self.state_dir / ADVANCED_STATE_NAME
        self.node_log_paths = {node: self.state_dir / f"synthetic-{node}-events.jsonl"
                               for node in ("node-alpha", "node-beta")}
        self.advanced_state = dict(ADVANCED_INITIAL)
        if enable_advanced and self.advanced_state_path.exists():
            saved = json.loads(self.advanced_state_path.read_text(encoding="utf-8"))
            if not isinstance(saved, dict) or set(saved) != set(ADVANCED_INITIAL):
                raise ValueError("invalid synthetic advanced persisted state")
            self.advanced_state = saved
        self.l4_role_state: dict[str, Any] | None = None
        if enable_l4 and self.l4_state_path.exists():
            saved = json.loads(self.l4_state_path.read_text(encoding="utf-8"))
            if (not isinstance(saved, dict) or saved.get("principal") != username
                    or saved.get("role") != L4_ROLE
                    or not isinstance(saved.get("expires_at_epoch"), (int, float))):
                raise ValueError("invalid synthetic L4 persisted state")
            self.l4_role_state = saved
        self.executions: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.lock = threading.RLock()
        self.execution_lock = threading.Lock()
        self.event_context = threading.local()
        self.audit_path = self.state_dir / "target-events.jsonl"
        if self.audit_path.is_file():
            with self.audit_path.open(encoding="utf-8") as stream:
                for line in stream:
                    row = json.loads(line)
                    if not isinstance(row, dict) or not row.get("event_id"):
                        raise ValueError("invalid persisted target audit event")
                    self.events.append(row)

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def emit(self, event: str, request_id: str, case_id: str, **fields: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
        context_run = getattr(self.event_context, "run_id", "")
        run_id = fields.pop("run_id", context_run)
        row = {"event_id": uuid4().hex, "time_utc": utc_now(), "event": event,
               "run_id": run_id, "request_id": request_id, "test_case_id": case_id,
               "simulation": True, **fields}
        if BLUE_OBSERVER_REQUIRED and (not run_id or not BLUE_OBSERVER_KEY):
            raise RuntimeError("target event lacks a Run identity or Blue Observer key")
        with self.lock:
            self.events.append(row)
            # Keep this in-memory target audit bounded for the long-running lab process.
            if len(self.events) > 2048:
                del self.events[:len(self.events) - 2048]
            if BLUE_OBSERVER_REQUIRED:
                self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                with self.audit_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
        ack = None
        if BLUE_OBSERVER_REQUIRED:
            deadline = getattr(self.event_context, "component_deadline_monotonic", None)
            ack = component_request(BLUE_OBSERVER_URL.rsplit("/", 1)[0], "/ingest",
                                    method="POST", run_id=run_id,
                                    case_id=case_id, request_id=request_id,
                                    body={"source": "target", "event": row}, observer=True,
                                    timeout_seconds=(L7_TRANSFER_COMPONENT_BUDGET_SECONDS
                                                     if deadline is not None
                                                     else COMPONENT_REQUEST_TIMEOUT_SECONDS),
                                    deadline_monotonic=deadline)
            if ack.get("accepted") is not True:
                raise RuntimeError("independent Blue Observer did not acknowledge target event")
        print(json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)
        return row, ack

    def execute_fixed(self, run_id: str, token: str, request_id: str, case_id: str) -> dict[str, Any]:
        if not RUN_RE.fullmatch(run_id):
            raise ValueError("invalid run id")
        with self.execution_lock:
            # Serialize session validation with Reset so a request authorized just
            # before a reset cannot start a child process after the reset completes.
            if not self.authorize(token, request_id, case_id):
                return {"run_id": run_id, "test_case_id": case_id, "request_id": request_id,
                        "outcome": "denied"}
            with self.lock:
                if request_id in self.executions:
                    raise RuntimeError("request already executed")
                self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                if self.marker_path.exists():
                    self.marker_path.unlink()
                for stale in self.state_dir.glob(f".{L3_MARKER_NAME}.*.tmp"):
                    stale.unlink()
            script_sha = hashlib.sha256(L3_SCRIPT.read_bytes()).hexdigest()
            started = utc_now()
            started_mono = time.monotonic()
            self.emit("l3_process_started", request_id, case_id, run_id=run_id,
                      script_id=L3_SCRIPT_ID, script_sha256=script_sha,
                      executable=Path(sys.executable).name)
            try:
                completed = subprocess.run(
                    [sys.executable, str(L3_SCRIPT), run_id, case_id, request_id,
                     str(self.marker_path)],
                    shell=False, check=False, capture_output=True, text=True, timeout=10,
                    cwd=str(self.state_dir),
                    env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
                )
            except (OSError, subprocess.SubprocessError) as exc:
                record = {"run_id": run_id, "test_case_id": case_id, "request_id": request_id,
                          "script_id": L3_SCRIPT_ID, "script_sha256": script_sha,
                          "started_utc": started, "completed_utc": utc_now(), "exit_status": None,
                          "outcome": "failed", "error_type": type(exc).__name__}
                with self.lock:
                    self.executions[request_id] = record
                self.emit("l3_execution_completed", request_id, case_id, run_id=run_id,
                          outcome="failed", exit_status=None, error_type=type(exc).__name__)
                return record
            completed_utc = utc_now()
            marker_sha = None
            marker = None
            if self.marker_path.is_file():
                marker_bytes = self.marker_path.read_bytes()
                marker_sha = hashlib.sha256(marker_bytes).hexdigest()
                try:
                    marker = json.loads(marker_bytes)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    marker = None
            ok = (completed.returncode == 0 and isinstance(marker, dict)
                  and marker.get("run_id") == run_id and marker.get("test_case_id") == case_id
                  and marker.get("request_id") == request_id
                  and marker.get("script_id") == L3_SCRIPT_ID
                  and marker.get("script_sha256") == script_sha
                  and marker.get("result") == 39)
            if not ok and self.marker_path.exists():
                self.marker_path.unlink()
                marker_sha = None
            record = {"run_id": run_id, "test_case_id": case_id, "request_id": request_id,
                      "script_id": L3_SCRIPT_ID, "script_sha256": script_sha,
                      "started_utc": started, "completed_utc": completed_utc,
                      "duration_ms": round((time.monotonic() - started_mono) * 1000, 3),
                      "exit_status": completed.returncode, "outcome": "completed" if ok else "failed",
                      "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                      "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
                      "marker_sha256": marker_sha}
            with self.lock:
                self.executions[request_id] = record
            self.emit("l3_execution_completed", request_id, case_id, run_id=run_id,
                      script_id=L3_SCRIPT_ID, script_sha256=script_sha,
                      started_utc=started, completed_utc=completed_utc,
                      exit_status=completed.returncode, outcome=record["outcome"],
                      marker_sha256=marker_sha)
            return record

    def inspect_l3(self, run_id: str, case_id: str, request_id: str) -> dict[str, Any]:
        with self.lock:
            record = self.executions.get(request_id)
            matching_events = [event.copy() for event in self.events
                               if event.get("request_id") == request_id
                               and event.get("test_case_id") == case_id
                               and event.get("run_id", run_id) == run_id]
            marker_exists = self.marker_path.is_file()
            marker_bytes = self.marker_path.read_bytes() if marker_exists else b""
        marker = None
        if marker_bytes:
            try:
                marker = json.loads(marker_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                marker = {"parse_error": True}
        if record is not None and (record.get("run_id") != run_id or record.get("test_case_id") != case_id):
            record = None
        if isinstance(marker, dict) and (marker.get("run_id") != run_id
                                         or marker.get("test_case_id") != case_id
                                         or marker.get("request_id") != request_id):
            marker = None
        return {"run_id": run_id, "test_case_id": case_id, "request_id": request_id,
                "execution": record, "marker_present": marker is not None,
                "marker": marker, "marker_sha256": hashlib.sha256(marker_bytes).hexdigest()
                if marker is not None else None, "events": matching_events}

    def login(self, username: str, password: str, request_id: str, case_id: str) -> str | None:
        user_ok = hmac.compare_digest(username.encode("utf-8"), self.username.encode("utf-8"))
        pass_ok = hmac.compare_digest(password.encode("utf-8"), self._password)
        if not (user_ok and pass_ok):
            self.emit("login_rejected", request_id, case_id, outcome="denied")
            return None
        token = secrets.token_urlsafe(32)
        digest = self.token_hash(token)
        with self.lock:
            self.sessions[digest] = (time.monotonic() + self.ttl, self.username)
        self.emit("login_succeeded", request_id, case_id, outcome="allow")
        self.emit("session_created", request_id, case_id, session_fingerprint=digest[:12], ttl_seconds=self.ttl)
        return token

    def authorize(self, token: str, request_id: str, case_id: str) -> bool:
        if not token:
            self.emit("protected_access_denied", request_id, case_id, reason="missing_session")
            return False
        digest = self.token_hash(token)
        now = time.monotonic()
        with self.lock:
            session = self.sessions.get(digest)
            if session and session[0] <= now:
                self.sessions.pop(digest, None)
                session = None
                reason = "expired_session"
            else:
                reason = "invalid_session"
        if not session:
            self.emit("protected_access_denied", request_id, case_id, reason=reason,
                      session_fingerprint=digest[:12])
            return False
        self.emit("protected_access_granted", request_id, case_id, session_fingerprint=digest[:12])
        return True

    def establish_l4_role(self, run_id: str, token: str, request_id: str,
                          case_id: str) -> dict[str, Any]:
        if not self.l4_enabled or not RUN_RE.fullmatch(run_id):
            raise ValueError("L4 synthetic action is unavailable")
        with self.execution_lock:
            if not self.authorize(token, request_id, case_id):
                return {"outcome": "denied"}
            with self.lock:
                if self.l4_role_state is not None and self.l4_role_state["expires_at_epoch"] > time.time():
                    raise RuntimeError("one synthetic role lease already exists; Reset is required")
                state = {"run_id": run_id, "test_case_id": case_id,
                         "request_id": request_id, "principal": self.username,
                         "role": L4_ROLE, "created_utc": utc_now(),
                         "expires_at_epoch": round(time.time() + L4_LEASE_SECONDS, 3),
                         "simulation": True}
                encoded = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
                self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                temporary = self.state_dir / f".{L4_ROLE_STATE_NAME}.{request_id}.tmp"
                temporary.write_bytes(encoded)
                os.replace(temporary, self.l4_state_path)
                self.l4_role_state = state
                state_sha = hashlib.sha256(encoded).hexdigest()
            self.emit("l4_synthetic_persistence_created", request_id, case_id,
                      run_id=run_id, state_sha256=state_sha, ttl_seconds=L4_LEASE_SECONDS)
            final_event, blue_ack = self.emit("l4_test_role_granted", request_id, case_id,
                      run_id=run_id, principal=self.username, role=L4_ROLE,
                      state_sha256=state_sha)
            return {"outcome": "completed", "run_id": run_id,
                    "test_case_id": case_id, "request_id": request_id,
                    "role": L4_ROLE, "state_sha256": state_sha,
                    "ttl_seconds": L4_LEASE_SECONDS, "simulation": True,
                    "target_event_id": final_event["event_id"], "blue_observer_ack": blue_ack}

    def l4_role_access(self, token: str, request_id: str, case_id: str) -> bool:
        if not self.l4_enabled or not self.authorize(token, request_id, case_id):
            return False
        with self.lock:
            active = (self.l4_role_state is not None
                      and self.l4_role_state["expires_at_epoch"] > time.time()
                      and self.l4_state_path.is_file()
                      and self.l4_role_state["principal"] == self.username)
        self.emit("l4_role_resource_" + ("granted" if active else "denied"),
                  request_id, case_id, role=L4_ROLE)
        return active

    def inspect_l4(self, run_id: str, case_id: str, request_id: str) -> dict[str, Any]:
        with self.lock:
            state = self.l4_role_state
            matches = [event.copy() for event in self.events
                       if event.get("run_id") == run_id
                       and event.get("test_case_id") == case_id
                       and event.get("request_id") == request_id]
            present = (state is not None and self.l4_state_path.is_file()
                       and state.get("run_id") == run_id
                       and state.get("test_case_id") == case_id
                       and state.get("request_id") == request_id
                       and state["expires_at_epoch"] > time.time())
            state_sha = hashlib.sha256(self.l4_state_path.read_bytes()).hexdigest() if present else None
        return {"run_id": run_id, "test_case_id": case_id, "request_id": request_id,
                "role_active": present, "state_sha256": state_sha,
                "role": L4_ROLE if present else None, "events": matches,
                "simulation": True}

    def perform_advanced(self, action: str, run_id: str, token: str,
                         request_id: str, case_id: str) -> dict[str, Any]:
        """Apply one fixed synthetic transition; network effects stay on the isolated lab."""
        if not self.advanced_enabled or action not in ADVANCED_ACTIONS or not RUN_RE.fullmatch(run_id):
            raise ValueError("advanced synthetic action unavailable")
        self.event_context.failure_stage = "advanced_precondition"
        deadline = None
        if action == "l7-transfer":
            # Keep the complete receiver + two Blue Observer calls below the
            # reviewed Gateway (7s) and Worker (8s) request limits.
            deadline = time.monotonic() + L7_TRANSFER_COMPONENT_BUDGET_SECONDS
            self.event_context.component_deadline_monotonic = deadline
        with self.execution_lock:
            if not self.authorize(token, request_id, case_id):
                return {"outcome": "denied"}
            with self.lock:
                if request_id in self.advanced_state["completed_request_ids"]:
                    raise RuntimeError("synthetic request already executed")
                if action in self.advanced_state["completed_actions"]:
                    raise RuntimeError("synthetic action already executed; Reset required")
                next_state = dict(self.advanced_state)
                next_state["completed_request_ids"] = list(self.advanced_state["completed_request_ids"])
                next_state["completed_actions"] = list(self.advanced_state["completed_actions"])
                if action == "l5-canary":
                    next_state["canary_accessed"] = True
                    details = {"canary_id": "LAB-CANARY-NONSECRET-01"}
                elif action == "l5-visibility":
                    next_state["visibility_mode"] = "simulated_degraded_visibility"
                    details = {"control_simulation": "degraded_visibility", "real_security_controls_changed": False}
                elif action == "l6-discovery":
                    next_state["discovered_nodes"] = ["node-alpha", "node-beta"]
                    details = {"node_ids": ["node-alpha", "node-beta"]}
                elif action == "l6-session":
                    if next_state["discovered_nodes"] != ["node-alpha", "node-beta"]:
                        return {"outcome": "precondition_missing"}
                    next_state["node_session_active"] = True
                    details = {"source_node": "node-alpha", "destination_node": "node-beta"}
                elif action == "l7-collection":
                    next_state["collected_ids"] = ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"]
                    details = {"record_ids": list(next_state["collected_ids"])}
                elif action == "l7-c2":
                    next_state["c2_heartbeat_count"] += 1
                    details = {"message": "LAB-NOOP", "ack": "LAB-NOOP-ACK"}
                elif action == "l7-transfer":
                    if next_state["collected_ids"] != ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"]:
                        return {"outcome": "precondition_missing"}
                    digest = hashlib.sha256(json.dumps(next_state["collected_ids"], sort_keys=True).encode()).hexdigest()
                    next_state["receiver_digest"] = digest
                    details = {"receiver_id": "lab-receiver-fixed", "payload_sha256": digest,
                               "external_network_used": False}
                else:
                    next_state["impact_mode"] = "simulated_interruption"
                    details = {"impact_mode": "simulated_interruption", "real_service_interrupted": False}
                if len(next_state["completed_request_ids"]) >= 128:
                    raise RuntimeError("advanced synthetic request ledger full; Reset required")
                next_state["completed_request_ids"].append(request_id)
                next_state["completed_actions"].append(action)
                encoded = (json.dumps(next_state, sort_keys=True, separators=(",", ":")) + "\n").encode()
                state_sha = hashlib.sha256(encoded).hexdigest()
            if SEPARATE_COMPONENTS_REQUIRED and action == "l6-discovery":
                observed = [component_request(COMPONENT_URLS[node], "/identity", method="GET",
                    run_id=run_id, case_id=case_id, request_id=request_id) for node in ("node-alpha", "node-beta")]
                if [row.get("node_id") for row in observed] != ["node-alpha", "node-beta"]:
                    raise RuntimeError("separate synthetic node discovery failed closed")
                details.update({"component_event_ids": [row.get("event_id") for row in observed],
                                "component_state_sha256": {row["node_id"]: row.get("state_sha256") for row in observed},
                                "separate_processes_verified": True})
            elif SEPARATE_COMPONENTS_REQUIRED and action == "l6-session":
                opened = component_request(COMPONENT_URLS["node-alpha"], "/session/open", method="POST",
                    run_id=run_id, case_id=case_id, request_id=request_id,
                    body={"purpose": "fixed-synthetic-session-v1"})
                if opened.get("status") != "opened" or not isinstance(opened.get("session_id"), str):
                    raise RuntimeError("separate source node did not open fixed session")
                accepted = component_request(COMPONENT_URLS["node-beta"], "/session/accept", method="POST",
                    run_id=run_id, case_id=case_id, request_id=request_id,
                    body={"session_id": opened["session_id"]})
                if accepted.get("status") != "accepted":
                    raise RuntimeError("separate destination node did not accept fixed session")
                details.update({"component_event_ids": [opened.get("event_id"), accepted.get("event_id")],
                                "component_state_sha256": {"node-alpha": opened.get("state_sha256"),
                                                           "node-beta": accepted.get("state_sha256")},
                                "separate_processes_verified": True})
            elif SEPARATE_COMPONENTS_REQUIRED and action == "l7-transfer":
                self.event_context.failure_stage = "receiver_request"
                accepted = component_request(COMPONENT_URLS["receiver"], "/accept", method="POST",
                    run_id=run_id, case_id=case_id, request_id=request_id,
                    body={"record_ids": next_state["collected_ids"], "payload_sha256": digest},
                    timeout_seconds=L7_TRANSFER_COMPONENT_BUDGET_SECONDS,
                    deadline_monotonic=deadline)
                self.event_context.failure_stage = "receiver_response_validation"
                if not valid_receiver_acceptance(accepted, digest):
                    raise ValueError("independent synthetic receiver response violates fixed contract")
                details.update({"receiver_event_id": accepted.get("event_id"),
                                "receiver_state_sha256": accepted.get("state_sha256"),
                                "separate_processes_verified": True})
            if action == "l6-session" and not SEPARATE_COMPONENTS_REQUIRED:
                for node, event_name in (("node-alpha", "l6_source_session_opened"),
                                         ("node-beta", "l6_destination_session_accepted")):
                    row = {"time_utc": utc_now(), "event": event_name, "run_id": run_id,
                           "test_case_id": case_id, "request_id": request_id,
                           "state_sha256": state_sha, "node_id": node, "simulation": True}
                    with self.node_log_paths[node].open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                    self.emit(event_name, request_id, case_id, run_id=run_id,
                              action=action, state_sha256=state_sha, node_id=node,
                              log_source=f"synthetic-{node}-file")
            with self.lock:
                self.event_context.failure_stage = "target_state_commit"
                self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                temporary = self.state_dir / f".{ADVANCED_STATE_NAME}.{request_id}.tmp"
                temporary.write_bytes(encoded)
                os.replace(temporary, self.advanced_state_path)
                self.advanced_state = next_state
            self.event_context.failure_stage = "target_blue_observer_notification"
            self.emit("advanced_action_requested", request_id, case_id,
                      run_id=run_id, action=action, state_sha256=state_sha)
            final_event, blue_ack = self.emit(ADVANCED_ACTIONS[action], request_id, case_id,
                      run_id=run_id, action=action, state_sha256=state_sha, **details)
            return {"outcome": "completed", "action": action, "run_id": run_id,
                    "test_case_id": case_id, "request_id": request_id,
                    "state_sha256": state_sha, "effect": details,
                    "target_event_id": final_event["event_id"],
                    "blue_observer_ack": blue_ack, "simulation": True}
    def inspect_advanced(self, run_id: str, case_id: str, request_id: str) -> dict[str, Any]:
        with self.lock:
            events = [row.copy() for row in self.events if row.get("run_id") == run_id
                      and row.get("test_case_id") == case_id and row.get("request_id") == request_id]
            state = dict(self.advanced_state)
            state_sha = hashlib.sha256(self.advanced_state_path.read_bytes()).hexdigest() if self.advanced_state_path.is_file() else None
            node_events = {}
            for node, path in self.node_log_paths.items():
                node_events[node] = ([row for line in path.read_text(encoding="utf-8").splitlines()
                                      if (row := json.loads(line)).get("run_id") == run_id
                                      and row.get("test_case_id") == case_id
                                      and row.get("request_id") == request_id]
                                     if path.is_file() else [])
        component_proofs: dict[str, Any] = {}
        if SEPARATE_COMPONENTS_REQUIRED:
            for role in ("node-alpha", "node-beta", "receiver"):
                component_proofs[role] = component_request(
                    COMPONENT_URLS[role], f"/snapshot?run_id={urllib.parse.quote(run_id)}"
                    f"&case_id={urllib.parse.quote(case_id)}&request_id={urllib.parse.quote(request_id)}",
                    method="GET", run_id=run_id, case_id=case_id, request_id=request_id)
        blue_proof = None
        if BLUE_OBSERVER_REQUIRED:
            blue_proof = component_request(BLUE_OBSERVER_URL.rsplit("/", 1)[0],
                f"/snapshot?run_id={urllib.parse.quote(run_id)}&case_id={urllib.parse.quote(case_id)}"
                f"&request_id={urllib.parse.quote(request_id)}", method="GET", run_id=run_id,
                case_id=case_id, request_id=request_id, observer=True)
        return {"run_id": run_id, "test_case_id": case_id, "request_id": request_id,
                "state": state, "state_sha256": state_sha, "events": events,
                "node_events": node_events,
                "separate_components": component_proofs, "blue_observer": blue_proof,
                "simulation": True}

    def reset_components(self, run_id: str, case_id: str, request_id: str) -> dict[str, Any]:
        # Each component synchronously publishes its reset to the independent
        # observer. Run the three bounded resets concurrently so one slow
        # observer acknowledgment cannot consume the gateway's entire budget.
        def reset_one(role: str) -> tuple[str, dict[str, Any]]:
            deadline = time.monotonic() + RESET_COMPONENT_BUDGET_SECONDS
            reset = component_request(COMPONENT_URLS[role], "/reset", method="POST",
                run_id=run_id, case_id=case_id, request_id=request_id, body={"reset": True},
                timeout_seconds=RESET_COMPONENT_BUDGET_SECONDS, deadline_monotonic=deadline)
            if reset.get("status") != "reset" or reset.get("cleared") is not True:
                raise RuntimeError(f"{role} reset was not confirmed")
            snapshot = component_request(COMPONENT_URLS[role],
                f"/snapshot?run_id={urllib.parse.quote(run_id)}&case_id={urllib.parse.quote(case_id)}"
                f"&request_id={urllib.parse.quote(request_id)}", method="GET", run_id=run_id,
                case_id=case_id, request_id=request_id,
                timeout_seconds=RESET_COMPONENT_BUDGET_SECONDS, deadline_monotonic=deadline)
            proof = {"reset_event_id": reset.get("event_id"),
                            "state_sha256": snapshot.get("state_sha256"),
                            "component": snapshot.get("component"), "pid": snapshot.get("pid")}
            if (not isinstance(proof["state_sha256"], str)
                    or len(proof["state_sha256"]) != 64
                    or proof["component"] != role
                    or not isinstance(proof["reset_event_id"], str)
                    or len(proof["reset_event_id"]) != 32
                    or snapshot.get("state") != COMPONENT_INITIAL_STATE[role]):
                raise RuntimeError(f"{role} reset state hash missing")
            return role, proof

        roles = ("node-alpha", "node-beta", "receiver")
        with ThreadPoolExecutor(max_workers=len(roles)) as executor:
            futures = {role: executor.submit(reset_one, role) for role in roles}
            results = [futures[role].result() for role in roles]
        proofs = {role: proof for role, proof in results}
        return proofs

    def reset(self, key: str, request_id: str, case_id: str) -> bool:
        if not hmac.compare_digest(key.encode("utf-8"), self._reset_key):
            self.emit("reset_rejected", request_id, case_id, outcome="denied")
            return False
        with self.execution_lock:
            with self.lock:
                self.sessions.clear()
                removed_marker = self.marker_path.exists()
                if removed_marker:
                    self.marker_path.unlink()
                removed_temp_files = []
                for stale in self.state_dir.glob(f".{L3_MARKER_NAME}.*.tmp"):
                    stale.unlink()
                    removed_temp_files.append(stale.name)
                self.executions.clear()
                prior_l4_state = self.l4_state_path.exists()
                if prior_l4_state:
                    self.l4_state_path.unlink()
                self.l4_role_state = None
                for stale in self.state_dir.glob(f".{L4_ROLE_STATE_NAME}.*.tmp"):
                    stale.unlink()
                prior_advanced_state = self.advanced_state_path.exists()
                if prior_advanced_state:
                    self.advanced_state_path.unlink()
                self.advanced_state = dict(ADVANCED_INITIAL)
                for stale in self.state_dir.glob(f".{ADVANCED_STATE_NAME}.*.tmp"):
                    stale.unlink()
                for path in self.node_log_paths.values():
                    if path.exists():
                        path.unlink()
            self.emit("state_reset", request_id, case_id, active_sessions=0,
                      l3_marker_cleared=not self.marker_path.exists(),
                      l3_temp_files_cleared=not any(self.state_dir.glob(f".{L3_MARKER_NAME}.*.tmp")),
                      prior_l3_marker_present=removed_marker,
                      prior_l3_temp_file_count=len(removed_temp_files),
                      l4_role_cleared=not self.l4_state_path.exists(),
                      prior_l4_role_present=prior_l4_state)
            self.emit("advanced_state_reset", request_id, case_id,
                      advanced_state_cleared=not self.advanced_state_path.exists(),
                      prior_advanced_state_present=prior_advanced_state)
        return True

    def verify_worker_ingress(self, method: str, path: str, request_id: str,
                              case_id: str, headers: Any, *, now_epoch: int | None = None) -> bool:
        if not self.worker_ingress_required or not worker_ingress_path_is_protected(path):
            return True
        run_id = headers.get("X-Run-ID", "")
        timestamp = headers.get("X-GADE-Worker-Timestamp", "")
        nonce = headers.get("X-GADE-Worker-Nonce", "")
        supplied = headers.get("X-GADE-Worker-Signature", "")
        if (method not in {"GET", "POST"} or not RUN_RE.fullmatch(run_id)
                or not re.fullmatch(r"[0-9]{10}", timestamp)
                or not re.fullmatch(r"[0-9a-f]{32}", nonce)
                or not re.fullmatch(r"[0-9a-f]{64}", supplied)):
            return False
        timestamp_epoch = int(timestamp)
        now = int(time.time()) if now_epoch is None else now_epoch
        if abs(now - timestamp_epoch) > WORKER_INGRESS_TIMESTAMP_SKEW_SECONDS:
            return False
        try:
            expected = worker_ingress_signature(self._password, method, path, run_id,
                                                case_id, request_id, timestamp, nonce)
        except ValueError:
            return False
        if not hmac.compare_digest(supplied, expected):
            return False
        with self.lock:
            self.worker_ingress_nonces = {
                seen: seen_at for seen, seen_at in self.worker_ingress_nonces.items()
                if now - seen_at <= WORKER_INGRESS_TIMESTAMP_SKEW_SECONDS
            }
            if nonce in self.worker_ingress_nonces:
                return False
            if len(self.worker_ingress_nonces) >= 8192:
                return False
            self.worker_ingress_nonces[nonce] = timestamp_epoch
        return True


class Handler(BaseHTTPRequestHandler):
    server_version = "M2A-L2-Lab"
    sys_version = ""

    @property
    def state(self) -> AuthState:
        return self.server.auth_state  # type: ignore[attr-defined]

    def log_message(self, _format: str, *_args: Any) -> None:
        # Default access logging can include attacker-controlled strings; structured
        # application events below carry only request/case IDs and safe metadata.
        return

    def _identity(self) -> tuple[str, str] | None:
        request_id = self.headers.get("X-Request-ID", "")
        case_id = self.headers.get("X-Test-Case-ID", "")
        if not REQUEST_RE.fullmatch(request_id) or not CASE_RE.fullmatch(case_id):
            return None
        run_id = self.headers.get("X-Run-ID", "")
        if run_id and not RUN_RE.fullmatch(run_id):
            return None
        # The deployed fixed L2 handler predates the Blue Observer and sends its
        # GADE run identity in the bounded case ID, without an X-Run-ID header.
        # Accept that legacy shape only for the two fixed L2 routes.  Other
        # synthetic actions still require their explicit run identity.
        if BLUE_OBSERVER_REQUIRED and not run_id and urlsplit(self.path).path in {
                "/lab/auth/login", "/lab/protected"}:
            match = GADE_L2_CASE_RUN_RE.fullmatch(case_id)
            if match is None:
                return None
            run_id = match.group(1)
        self.state.event_context.run_id = run_id
        return request_id, case_id

    def _reply(self, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _json_body(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if not 0 < length <= MAX_BODY:
            return None
        if self.headers.get_content_type() != "application/json":
            return None
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def do_GET(self) -> None:  # noqa: N802
        ident = self._identity()
        parsed = urlsplit(self.path)
        if parsed.path == "/lab/healthz":
            self._reply(200, {"status": "ok", "scenario":
                "gade-a-d7-synthetic" if SEPARATE_COMPONENTS_REQUIRED else "gade-l2-t1078"})
            return
        if ident is None:
            self._reply(400, {"error": "request and test-case IDs required"})
            return
        request_id, case_id = ident
        if not self.state.verify_worker_ingress("GET", parsed.path, request_id,
                                                case_id, self.headers):
            self.state.emit("worker_ingress_denied", request_id, case_id,
                            method="GET", path=parsed.path)
            self.close_connection = True
            self._reply(403, {"error": "worker_ingress_proof_required"})
            return
        if parsed.path == "/lab/admin/l3-evidence":
            supplied_key = self.headers.get("X-Lab-Reset-Key", "")
            if not hmac.compare_digest(supplied_key.encode("utf-8"), self.state._reset_key):
                self._reply(403, {"error": "inspection_denied"})
                return
            query = parse_qs(parsed.query, strict_parsing=True)
            run_id = query.get("run_id", [""])[0]
            case_id = query.get("case_id", [""])[0]
            request_id = query.get("request_id", [""])[0]
            if not (RUN_RE.fullmatch(run_id) and CASE_RE.fullmatch(case_id)
                    and REQUEST_RE.fullmatch(request_id)):
                self._reply(400, {"error": "invalid_identity"})
                return
            self._reply(200, self.state.inspect_l3(run_id, case_id, request_id))
            return
        if parsed.path == "/lab/admin/l4-evidence":
            supplied_key = self.headers.get("X-Lab-Reset-Key", "")
            if not hmac.compare_digest(supplied_key.encode("utf-8"), self.state._reset_key):
                self._reply(403, {"error": "inspection_denied"})
                return
            query = parse_qs(parsed.query, strict_parsing=True)
            run_id = query.get("run_id", [""])[0]
            proof_case = query.get("case_id", [""])[0]
            proof_request = query.get("request_id", [""])[0]
            if not (RUN_RE.fullmatch(run_id) and CASE_RE.fullmatch(proof_case)
                    and REQUEST_RE.fullmatch(proof_request)):
                self._reply(400, {"error": "invalid_identity"})
                return
            self._reply(200, self.state.inspect_l4(run_id, proof_case, proof_request))
            return
        if parsed.path == "/lab/admin/advanced-evidence":
            supplied_key = self.headers.get("X-Lab-Reset-Key", "")
            if not hmac.compare_digest(supplied_key.encode("utf-8"), self.state._reset_key):
                self._reply(403, {"error": "inspection_denied"})
                return
            query = parse_qs(parsed.query, strict_parsing=True)
            run_id = query.get("run_id", [""])[0]
            proof_case = query.get("case_id", [""])[0]
            proof_request = query.get("request_id", [""])[0]
            if not (RUN_RE.fullmatch(run_id) and CASE_RE.fullmatch(proof_case)
                    and REQUEST_RE.fullmatch(proof_request)):
                self._reply(400, {"error": "invalid_identity"})
                return
            try:
                proof = self.state.inspect_advanced(run_id, proof_case, proof_request)
            except (OSError, ValueError, URLError, TimeoutError) as exc:
                self._reply(503, {"error": "independent_evidence_unavailable",
                                  "error_type": type(exc).__name__})
                return
            self._reply(200, proof)
            return
        if parsed.path == "/lab/l4/protected":
            if not self.state.l4_enabled:
                self._reply(404, {"error": "not_found"})
                return
            bearer = self.headers.get("Authorization", "")
            token = bearer[7:] if bearer.startswith("Bearer ") else ""
            if not self.state.l4_role_access(token, request_id, case_id):
                self._reply(403, {"error": "synthetic_role_required"})
                return
            self._reply(200, {"resource": "lab-only-l4-role-resource", "role": L4_ROLE,
                              "simulation": True})
            return
        if parsed.path == "/lab/protected":
            pass
        else:
            self.state.emit("route_not_found", request_id, case_id)
            self._reply(404, {"error": "not_found"})
            return
        bearer = self.headers.get("Authorization", "")
        token = bearer[7:] if bearer.startswith("Bearer ") else ""
        if not self.state.authorize(token, request_id, case_id):
            self._reply(401, {"error": "authentication_required"})
            return
        self._reply(200, {"resource": "lab-only-protected-resource", "scenario": "T1078-test-account",
                          "test_case_id": case_id, "access": "granted"})

    def do_POST(self) -> None:  # noqa: N802
        ident = self._identity()
        if ident is None:
            self._reply(400, {"error": "request and test-case IDs required"})
            return
        request_id, case_id = ident
        path = urlsplit(self.path).path
        if not self.state.verify_worker_ingress("POST", path, request_id,
                                                case_id, self.headers):
            self.state.emit("worker_ingress_denied", request_id, case_id,
                            method="POST", path=path)
            self.close_connection = True
            self._reply(403, {"error": "worker_ingress_proof_required"})
            return
        body = self._json_body()
        if body is None:
            self.state.emit("request_rejected", request_id, case_id, reason="invalid_json")
            self._reply(400, {"error": "invalid_request"})
            return
        if self.path == "/lab/auth/login":
            username = body.get("username")
            password = body.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                self._reply(400, {"error": "invalid_request"})
                return
            token = self.state.login(username, password, request_id, case_id)
            if token is None:
                self._reply(401, {"error": "invalid_credentials"})
            else:
                self._reply(200, {"session_token": token, "expires_in": self.state.ttl,
                                  "test_case_id": case_id})
            return
        if self.path == "/lab/execute":
            run_id = self.headers.get("X-Run-ID", "")
            if not RUN_RE.fullmatch(run_id) or body != {}:
                self.state.emit("l3_execution_denied", request_id, case_id, run_id=run_id or None,
                                reason="invalid_fixed_request")
                self._reply(400, {"error": "invalid_request"})
                return
            bearer = self.headers.get("Authorization", "")
            token = bearer[7:] if bearer.startswith("Bearer ") else ""
            try:
                result = self.state.execute_fixed(run_id, token, request_id, case_id)
            except RuntimeError:
                self.state.emit("l3_execution_denied", request_id, case_id, run_id=run_id,
                                reason="duplicate_request")
                self._reply(409, {"error": "request_already_executed"})
                return
            if result["outcome"] == "denied":
                self._reply(401, {"error": "authentication_required"})
                return
            if result["outcome"] != "completed":
                self._reply(500, {"error": "fixed_execution_failed", "execution": result})
                return
            self._reply(200, {"status": "completed", "run_id": run_id,
                              "test_case_id": case_id, "request_id": request_id,
                              "script_id": result["script_id"], "script_sha256": result["script_sha256"],
                              "exit_status": result["exit_status"],
                              "marker_sha256": result["marker_sha256"]})
            return
        if self.path == "/lab/l4/role-lease":
            if not self.state.l4_enabled:
                self._reply(404, {"error": "not_found"})
                return
            run_id = self.headers.get("X-Run-ID", "")
            if not RUN_RE.fullmatch(run_id) or body != {}:
                self.state.emit("l4_role_lease_denied", request_id, case_id,
                                reason="invalid_fixed_request")
                self._reply(400, {"error": "invalid_request"})
                return
            bearer = self.headers.get("Authorization", "")
            token = bearer[7:] if bearer.startswith("Bearer ") else ""
            try:
                result = self.state.establish_l4_role(run_id, token, request_id, case_id)
            except RuntimeError:
                self._reply(409, {"error": "synthetic_role_lease_exists"})
                return
            if result["outcome"] == "denied":
                self._reply(401, {"error": "authentication_required"})
                return
            self._reply(200, result)
            return
        if self.path.startswith("/lab/advanced/"):
            action = self.path.removeprefix("/lab/advanced/")
            if not self.state.advanced_enabled or action not in ADVANCED_ACTIONS:
                self._reply(404, {"error": "not_found"})
                return
            run_id = self.headers.get("X-Run-ID", "")
            if not RUN_RE.fullmatch(run_id) or body != {}:
                self._reply(400, {"error": "invalid_fixed_request"})
                return
            bearer = self.headers.get("Authorization", "")
            token = bearer[7:] if bearer.startswith("Bearer ") else ""
            try:
                result = self.state.perform_advanced(action, run_id, token, request_id, case_id)
            except (RuntimeError, OSError, ValueError, TimeoutError) as exc:
                status = 409 if "already" in str(exc) or "precondition" in str(exc) else 503
                self._reply(status, {"error": "fixed_synthetic_action_failed",
                                     "error_type": type(exc).__name__,
                                     "failed_stage": getattr(self.state.event_context,
                                                              "failure_stage", "advanced_action"),
                                     "failure_code": synthetic_failure_code(
                                         exc, getattr(self.state.event_context,
                                                      "failure_stage", "advanced_action"))})
                return
            self._reply(200 if result["outcome"] == "completed" else 409, result)
            return
        if self.path == "/lab/admin/reset":
            key = body.get("reset_key")
            if not isinstance(key, str) or not self.state.reset(key, request_id, case_id):
                self._reply(403, {"error": "reset_denied"})
            else:
                try:
                    component_reset = (self.state.reset_components(
                        self.headers.get("X-Run-ID", ""), case_id, request_id)
                        if SEPARATE_COMPONENTS_REQUIRED else {})
                except (OSError, ValueError, URLError, TimeoutError, RuntimeError) as exc:
                    self._reply(503, {"error": "separate_component_reset_unverified",
                                      "error_type": type(exc).__name__})
                    return
                self._reply(200, {"status": "reset", "active_sessions": 0,
                                  "l3_marker_cleared": not self.state.marker_path.exists(),
                                  "l3_temp_files_cleared": not any(self.state.state_dir.glob(f".{L3_MARKER_NAME}.*.tmp")),
                                  "l4_role_cleared": not self.state.l4_state_path.exists(),
                                  "advanced_state_cleared": not self.state.advanced_state_path.exists(),
                                  "separate_component_reset": component_reset,
                                  "test_case_id": case_id})
            return
        self.state.emit("route_not_found", request_id, case_id)
        self._reply(404, {"error": "not_found"})


def main() -> None:
    if BLUE_OBSERVER_REQUIRED and not SEPARATE_COMPONENTS_REQUIRED:
        raise RuntimeError("office lab requires separate synthetic services")
    if SEPARATE_COMPONENTS_REQUIRED:
        expected_urls = {"node-alpha": "http://node-alpha:8091",
                         "node-beta": "http://node-beta:8091",
                         "receiver": "http://receiver:8092"}
        if (COMPONENT_URLS != expected_urls
                or BLUE_OBSERVER_URL != "http://blue-observer:8090/ingest"
                or len(COMPONENT_API_KEY) < 32 or len(BLUE_OBSERVER_KEY) < 32):
            raise RuntimeError("fixed isolated synthetic service configuration is incomplete")
        if (os.environ.get("GADE_L4_SYNTHETIC_ENABLED") != "1"
                or os.environ.get("GADE_ADVANCED_SYNTHETIC_ENABLED") != "1"):
            raise RuntimeError("isolated engineering profile requires explicit synthetic Action enablement")
        if not WORKER_INGRESS_AUTH_REQUIRED:
            raise RuntimeError("separate office synthetic services require Worker ingress authentication")
    state = AuthState(
        os.environ.get("GADE_L2_TEST_USERNAME", ""),
        os.environ.get("GADE_L2_TEST_PASSWORD", ""),
        os.environ.get("GADE_L2_RESET_KEY", ""),
        int(os.environ.get("GADE_L2_SESSION_TTL_SECONDS", "60")),
        enable_l4=os.environ.get("GADE_L4_SYNTHETIC_ENABLED") == "1",
        enable_advanced=os.environ.get("GADE_ADVANCED_SYNTHETIC_ENABLED") == "1",
    )
    state.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", 8081), Handler)
    server.auth_state = state  # type: ignore[attr-defined]
    print(json.dumps({"time_utc": utc_now(), "event": "server_started", "port": 8081,
                      "scenario": ("gade-a-d7-synthetic" if SEPARATE_COMPONENTS_REQUIRED
                                   else "gade-l2-t1078"),
                      "session_ttl_seconds": state.ttl}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

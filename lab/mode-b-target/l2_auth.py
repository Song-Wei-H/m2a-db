"""Minimal isolated valid-account/session scenario; Python standard library only."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

CASE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
REQUEST_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
RUN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
MAX_BODY = 4096
L3_SCRIPT = Path(__file__).with_name("l3_execution_task.py")
L3_SCRIPT_ID = "gade-controlled-python-execution-v1"
L3_MARKER_NAME = "execution-marker.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuthState:
    def __init__(self, username: str, password: str, reset_key: str, ttl: int = 60,
                 state_dir: str | Path | None = None):
        if not username or len(password) < 24 or len(reset_key) < 24:
            raise ValueError("test account configuration is missing or too short")
        if not 1 <= ttl <= 600:
            raise ValueError("session TTL must be between 1 and 600 seconds")
        self.username = username
        self._password = password.encode("utf-8")
        self._reset_key = reset_key.encode("utf-8")
        self.ttl = ttl
        self.sessions: dict[str, tuple[float, str]] = {}
        self.state_dir = Path(state_dir or os.environ.get("GADE_L3_STATE_DIR", "/tmp/gade-l3"))
        self.marker_path = self.state_dir / L3_MARKER_NAME
        self.executions: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.lock = threading.RLock()
        self.execution_lock = threading.Lock()

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def emit(self, event: str, request_id: str, case_id: str, **fields: Any) -> None:
        row = {"time_utc": utc_now(), "event": event, "request_id": request_id,
               "test_case_id": case_id, **fields}
        with self.lock:
            self.events.append(row)
            # Keep this in-memory target audit bounded for the long-running lab process.
            if len(self.events) > 2048:
                del self.events[:len(self.events) - 2048]
        print(json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)

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
            self.emit("state_reset", request_id, case_id, active_sessions=0,
                      l3_marker_cleared=not self.marker_path.exists(),
                      l3_temp_files_cleared=not any(self.state_dir.glob(f".{L3_MARKER_NAME}.*.tmp")),
                      prior_l3_marker_present=removed_marker,
                      prior_l3_temp_file_count=len(removed_temp_files))
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
            self._reply(200, {"status": "ok", "scenario": "gade-l2-t1078"})
            return
        if ident is None:
            self._reply(400, {"error": "request and test-case IDs required"})
            return
        request_id, case_id = ident
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
        if self.path == "/lab/admin/reset":
            key = body.get("reset_key")
            if not isinstance(key, str) or not self.state.reset(key, request_id, case_id):
                self._reply(403, {"error": "reset_denied"})
            else:
                self._reply(200, {"status": "reset", "active_sessions": 0,
                                  "l3_marker_cleared": not self.state.marker_path.exists(),
                                  "l3_temp_files_cleared": not any(self.state.state_dir.glob(f".{L3_MARKER_NAME}.*.tmp")),
                                  "test_case_id": case_id})
            return
        self.state.emit("route_not_found", request_id, case_id)
        self._reply(404, {"error": "not_found"})


def main() -> None:
    state = AuthState(
        os.environ.get("GADE_L2_TEST_USERNAME", ""),
        os.environ.get("GADE_L2_TEST_PASSWORD", ""),
        os.environ.get("GADE_L2_RESET_KEY", ""),
        int(os.environ.get("GADE_L2_SESSION_TTL_SECONDS", "60")),
    )
    state.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", 8081), Handler)
    server.auth_state = state  # type: ignore[attr-defined]
    print(json.dumps({"time_utc": utc_now(), "event": "server_started", "port": 8081,
                      "scenario": "gade-l2-t1078", "session_ttl_seconds": state.ttl}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

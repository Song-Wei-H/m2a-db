from __future__ import annotations

import contextlib
import importlib.util
import json
import secrets
import shutil
import threading
import time
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

MODULE_PATH = Path(__file__).parents[1] / "lab/mode-b-target/l2_auth.py"
SPEC = importlib.util.spec_from_file_location("mode_b_l3_auth", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class Lab:
    def __init__(self):
        state_dir = Path(__file__).parents[1] / "reports/local-only" / f"l3-test-{uuid.uuid4().hex}"
        state_dir.mkdir(parents=True)
        self.test_dir = state_dir
        self.username = "l3-test-user"
        self.password = secrets.token_urlsafe(32)
        self.reset_key = secrets.token_urlsafe(32)
        self.state = MODULE.AuthState(self.username, self.password, self.reset_key,
                                      ttl=60, state_dir=state_dir)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), MODULE.Handler)
        self.server.auth_state = self.state
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        shutil.rmtree(self.test_dir)

    def call(self, method: str, path: str, request_id: str, case_id: str,
             *, run_id: str | None = None, body: dict | None = None,
             token: str | None = None, admin: bool = False):
        headers = {"X-Request-ID": request_id, "X-Test-Case-ID": case_id}
        if run_id:
            headers["X-Run-ID"] = run_id
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if admin:
            headers["X-Lab-Reset-Key"] = self.reset_key
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with build_opener(ProxyHandler({})).open(req, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())


def test_l3_requires_session_executes_fixed_child_and_target_inspection_is_independent(capsys):
    lab = Lab()
    run_id, case_id = "L3-RUN-001", "L3-CASE-VALID"
    try:
        status, _ = lab.call("POST", "/lab/execute", "req-no-session", case_id,
                             run_id=run_id, body={})
        assert status == 401
        assert not lab.state.marker_path.exists()

        status, login = lab.call("POST", "/lab/auth/login", "req-login", case_id,
                                 body={"username": lab.username, "password": lab.password})
        assert status == 200
        token = login["session_token"]

        status, result = lab.call("POST", "/lab/execute", "req-execute", case_id,
                                  run_id=run_id, body={}, token=token)
        assert status == 200
        assert result["status"] == "completed"
        assert result["exit_status"] == 0
        assert result["script_id"] == "gade-controlled-python-execution-v1"
        status, _ = lab.call("POST", "/lab/execute", "req-execute", case_id,
                             run_id=run_id, body={}, token=token)
        assert status == 409  # A request ID cannot cause a second child process.

        status, proof = lab.call("GET", "/lab/admin/l3-evidence?" + urlencode({
            "run_id": run_id, "case_id": case_id, "request_id": "req-execute"
        }), "req-inspect", case_id, run_id=run_id, admin=True)
        assert status == 200
        assert proof["marker_present"] is True
        assert proof["marker"]["marker"] == "GADE-L3-CONTROLLED-EXECUTION-COMPLETE"
        assert proof["marker"]["result"] == 39
        assert proof["execution"]["outcome"] == "completed"
        assert proof["execution"]["exit_status"] == 0
        assert proof["marker_sha256"] == result["marker_sha256"]
        assert {event["event"] for event in proof["events"]} >= {
            "protected_access_granted", "l3_process_started", "l3_execution_completed"
        }
        logs = capsys.readouterr().out
        assert "l3_process_started" in logs and "l3_execution_completed" in logs
        assert lab.password not in logs and token not in logs and lab.reset_key not in logs
    finally:
        lab.close()


def test_l3_invalid_expired_sessions_do_not_execute():
    lab = Lab()
    case_id = "L3-CASE-DENIED"
    try:
        status, _ = lab.call("POST", "/lab/execute", "req-invalid", case_id,
                             run_id="L3-RUN-002", body={}, token="invalid-session")
        assert status == 401
        assert not lab.state.marker_path.exists()

        token = lab.state.login(lab.username, lab.password, "req-login-exp", case_id)
        assert token
        lab.state.sessions[lab.state.token_hash(token)] = (time.monotonic() - 1, lab.username)
        status, _ = lab.call("POST", "/lab/execute", "req-expired", case_id,
                             run_id="L3-RUN-002", body={}, token=token)
        assert status == 401
        assert not lab.state.marker_path.exists()
    finally:
        lab.close()


def test_l3_rejects_caller_supplied_command_or_parameters():
    lab = Lab()
    try:
        token = lab.state.login(lab.username, lab.password, "req-login-fixed", "L3-CASE-FIXED")
        assert token
        status, _ = lab.call("POST", "/lab/execute", "req-arbitrary", "L3-CASE-FIXED",
                             run_id="L3-RUN-FIXED", body={"command": "python -c anything"}, token=token)
        assert status == 400
        assert not lab.state.marker_path.exists()
        assert not lab.state.executions
    finally:
        lab.close()


def test_l3_reset_clears_marker_invalidates_old_session_and_repeat_is_reproducible():
    lab = Lab()
    run_id = "L3-RUN-003"
    try:
        assert lab.call("POST", "/lab/admin/reset", "req-reset-0", "L3-CASE-RESET",
                        body={"reset_key": lab.reset_key})[0] == 200
        status, login = lab.call("POST", "/lab/auth/login", "req-login-1", "L3-CASE-ONE",
                                 body={"username": lab.username, "password": lab.password})
        assert status == 200
        old_token = login["session_token"]
        status, first = lab.call("POST", "/lab/execute", "req-execute-1", "L3-CASE-ONE",
                                 run_id=run_id, body={}, token=old_token)
        assert status == 200
        first_marker_hash = first["marker_sha256"]
        assert lab.state.marker_path.exists()
        stale_temp = lab.state.state_dir / ".execution-marker.json.stale.tmp"
        stale_temp.write_text("partial", encoding="utf-8")

        status, reset = lab.call("POST", "/lab/admin/reset", "req-reset-1", "L3-CASE-RESET",
                                 body={"reset_key": lab.reset_key})
        assert status == 200 and reset["active_sessions"] == 0
        assert reset["l3_marker_cleared"] is True
        assert reset["l3_temp_files_cleared"] is True
        assert not lab.state.marker_path.exists()
        assert not stale_temp.exists()
        status, _ = lab.call("POST", "/lab/execute", "req-old-session", "L3-CASE-ONE",
                             run_id=run_id, body={}, token=old_token)
        assert status == 401
        assert not lab.state.marker_path.exists()

        status, login2 = lab.call("POST", "/lab/auth/login", "req-login-2", "L3-CASE-TWO",
                                  body={"username": lab.username, "password": lab.password})
        assert status == 200
        status, second = lab.call("POST", "/lab/execute", "req-execute-2", "L3-CASE-TWO",
                                  run_id=run_id, body={}, token=login2["session_token"])
        assert status == 200
        status, first_proof = lab.call("GET", "/lab/admin/l3-evidence?" + urlencode({
            "run_id": run_id, "case_id": "L3-CASE-ONE", "request_id": "req-execute-1"
        }), "req-inspect-1", "L3-CASE-ONE", run_id=run_id, admin=True)
        assert status == 200 and first_proof["marker_present"] is False  # Reset removed it.
        marker = json.loads(lab.state.marker_path.read_bytes())
        assert second["script_sha256"] == first["script_sha256"]
        assert marker["result"] == 39
        assert marker["marker"] == "GADE-L3-CONTROLLED-EXECUTION-COMPLETE"
        assert second["marker_sha256"] != first_marker_hash  # Request/time identity is part of each marker.
    finally:
        lab.close()


def test_l3_execution_failure_is_not_reported_as_success(monkeypatch):
    lab = Lab()
    try:
        token = lab.state.login(lab.username, lab.password, "req-login-fail", "L3-CASE-FAIL")
        assert token
        original = MODULE.subprocess.run
        monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **k: __import__("subprocess").CompletedProcess(
            args=a[0], returncode=17, stdout="", stderr="controlled test failure"))
        status, result = lab.call("POST", "/lab/execute", "req-fail", "L3-CASE-FAIL",
                                  run_id="L3-RUN-FAIL", body={}, token=token)
        assert status == 500
        assert result["error"] == "fixed_execution_failed"
        assert result["execution"]["outcome"] == "failed"
        assert not lab.state.marker_path.exists()
        proof_status, proof = lab.call("GET", "/lab/admin/l3-evidence?" + urlencode({
            "run_id": "L3-RUN-FAIL", "case_id": "L3-CASE-FAIL", "request_id": "req-fail"
        }), "req-inspect-fail", "L3-CASE-FAIL", run_id="L3-RUN-FAIL", admin=True)
        assert proof_status == 200 and proof["marker_present"] is False
        monkeypatch.setattr(MODULE.subprocess, "run", original)
    finally:
        lab.close()

"""Local-only L4 synthetic state and offline detection contract tests."""

import importlib.util
import json
import secrets
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener


ROOT = Path(__file__).parents[1] / "lab" / "mode-b-target"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


auth = load("l2_auth")
detector = load("blue_detection")


def test_l4_contract_is_fixed_home_scope_and_requires_individual_approval():
    contract = json.loads((ROOT.parents[1] / "home-lab" / "action-contracts"
                           / "l4-synthetic-role-lease-v1.json").read_text(encoding="utf-8"))
    assert contract["required_depth"] == 4
    assert contract["target"] == "127.0.0.1:18080"
    assert contract["scope"] == "127.0.0.1/32"
    assert contract["request"] == {"method": "POST", "path": "/lab/l4/role-lease",
                                   "body": {}, "run_id_header_required": True,
                                   "authenticated_test_session_required": True}
    assert contract["governance"]["individual_human_approval_required"] is True
    assert contract["governance"]["grant_execution_limit"] == 1
    assert contract["status"] == "TARGET_AND_OFFLINE_RULE_TESTED_WORKER_GADE_NOT_YET_ENABLED"


class Lab:
    def __init__(self, state_dir: Path, *, enable_l4: bool):
        self.username = "synthetic-l4-user"
        self.password = secrets.token_urlsafe(32)
        self.reset_key = secrets.token_urlsafe(32)
        self.state = auth.AuthState(self.username, self.password, self.reset_key,
                                    state_dir=state_dir, enable_l4=enable_l4)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), auth.Handler)
        self.server.auth_state = self.state
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def call(self, method: str, path: str, request_id: str, *, case_id="L4-CASE",
             run_id="L4-RUN", body=None, token=None, admin=False):
        headers = {"X-Request-ID": request_id, "X-Test-Case-ID": case_id,
                   "X-Run-ID": run_id}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if admin:
            headers["X-Lab-Reset-Key"] = self.reset_key
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        request = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with build_opener(ProxyHandler({})).open(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)


def test_l4_disabled_by_default_and_rejects_unreviewed_action(tmp_path):
    lab = Lab(tmp_path, enable_l4=False)
    try:
        status, _ = lab.call("POST", "/lab/l4/role-lease", "disabled", body={})
        assert status == 404
        assert not lab.state.l4_state_path.exists()
    finally:
        lab.close()


def test_l4_role_changes_behavior_persists_restarts_and_resets(tmp_path, capsys):
    lab = Lab(tmp_path, enable_l4=True)
    try:
        status, _ = lab.call("GET", "/lab/l4/protected", "before")
        assert status == 403
        status, _ = lab.call("POST", "/lab/l4/role-lease", "no-session", body={})
        assert status == 401
        status, login = lab.call("POST", "/lab/auth/login", "login", body={
            "username": lab.username, "password": lab.password})
        assert status == 200
        token = login["session_token"]
        status, _ = lab.call("POST", "/lab/l4/role-lease", "arbitrary", body={"role": "admin"}, token=token)
        assert status == 400
        status, created = lab.call("POST", "/lab/l4/role-lease", "l4-action", body={}, token=token)
        assert status == 200 and created["simulation"] is True
        assert created["role"] == auth.L4_ROLE
        assert lab.state.l4_state_path.is_file()
        status, _ = lab.call("POST", "/lab/l4/role-lease", "l4-action", body={}, token=token)
        assert status == 409
        status, resource = lab.call("GET", "/lab/l4/protected", "role-access", token=token)
        assert status == 200 and resource["resource"] == "lab-only-l4-role-resource"
        proof_path = "/lab/admin/l4-evidence?" + urlencode({
            "run_id": "L4-RUN", "case_id": "L4-CASE", "request_id": "l4-action"})
        assert lab.call("GET", proof_path, "inspect-denied")[0] == 403
        status, proof = lab.call("GET", proof_path, "inspect", admin=True)
        assert status == 200 and proof["role_active"] is True
        assert proof["state_sha256"] == created["state_sha256"]
        alerts = detector.detect_l4_role_lease(proof["events"])
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == detector.L4_RULE_ID
        assert alerts[0]["detection_latency_ms"] >= 0
        assert detector.detect_l4_role_lease(proof["events"][:1]) == []

        # The synthetic role survives process-state reconstruction from tmpfs;
        # a fresh session is still needed to use it.
        restarted = auth.AuthState(lab.username, lab.password, lab.reset_key,
                                   state_dir=tmp_path, enable_l4=True)
        assert restarted.l4_role_state is not None
        assert restarted.l4_role_access("", "restarted-denied", "L4-CASE") is False
        new_token = restarted.login(lab.username, lab.password, "restarted-login", "L4-CASE")
        assert new_token and restarted.l4_role_access(new_token, "restarted-access", "L4-CASE") is True

        status, reset = lab.call("POST", "/lab/admin/reset", "reset", body={"reset_key": lab.reset_key})
        assert status == 200 and reset["l4_role_cleared"] is True
        assert not lab.state.l4_state_path.exists()
        assert lab.call("GET", "/lab/l4/protected", "after-reset", token=token)[0] == 403
        assert lab.call("GET", proof_path, "inspect-after", admin=True)[1]["role_active"] is False
        output = capsys.readouterr().out
        assert token not in output and lab.password not in output and lab.reset_key not in output
    finally:
        lab.close()


def test_l4_blue_rule_requires_two_matching_events_and_order():
    base = {"run_id": "r", "test_case_id": "c", "request_id": "q",
            "state_sha256": "a" * 64}
    created = {**base, "event": "l4_synthetic_persistence_created",
               "time_utc": "2026-10-18T00:00:00.000Z"}
    granted = {**base, "event": "l4_test_role_granted",
               "time_utc": "2026-10-18T00:00:00.010Z"}
    assert detector.detect_l4_role_lease([created, granted])[0]["detection_latency_ms"] == 10
    assert detector.detect_l4_role_lease([created, {**granted, "request_id": "other"}]) == []
    assert detector.detect_l4_role_lease([granted, created]) == []

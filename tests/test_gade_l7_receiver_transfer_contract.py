"""Focused offline L7 receiver/Target contract and timeout-budget tests."""

import hashlib
import importlib.util
import json
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Barrier, Event, Thread

import pytest


TARGET_DIR = Path(__file__).resolve().parents[1] / "lab" / "mode-b-target"


def load_module(name):
    spec = importlib.util.spec_from_file_location(f"l7_contract_{name}", TARGET_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def expected_digest():
    return hashlib.sha256(json.dumps(
        ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"], sort_keys=True
    ).encode()).hexdigest()


def test_reset_checks_three_independent_components_with_bounded_parallel_requests(monkeypatch, tmp_path):
    auth = load_module("l2_auth")
    state = auth.AuthState("lab-user", "p" * 32, "r" * 32, state_dir=tmp_path,
                           enable_advanced=True)
    started = Barrier(3, timeout=2)
    calls = []

    def fake_request(url, path, **kwargs):
        role = next(name for name, base in auth.COMPONENT_URLS.items() if base == url)
        calls.append((role, path, kwargs["timeout_seconds"], kwargs["deadline_monotonic"]))
        if path == "/reset":
            started.wait()
            return {"status": "reset", "cleared": True, "event_id": "a" * 32}
        return {"state_sha256": "b" * 64, "component": role, "pid": 123,
                "state": auth.COMPONENT_INITIAL_STATE[role]}

    monkeypatch.setattr(auth, "component_request", fake_request)
    proofs = state.reset_components("run", "case", "request")
    assert set(proofs) == {"node-alpha", "node-beta", "receiver"}
    assert len(calls) == 6
    assert all(timeout == auth.RESET_COMPONENT_BUDGET_SECONDS and deadline > 0
               for _, _, timeout, deadline in calls)


@pytest.mark.parametrize("failure", ["bad_state", "timeout"])
def test_reset_fails_closed_when_any_separate_component_is_unverified(monkeypatch, tmp_path, failure):
    auth = load_module("l2_auth")
    state = auth.AuthState("lab-user", "p" * 32, "r" * 32, state_dir=tmp_path,
                           enable_advanced=True)

    def fake_request(url, path, **_kwargs):
        role = next(name for name, base in auth.COMPONENT_URLS.items() if base == url)
        if role == "receiver" and failure == "timeout":
            raise TimeoutError("synthetic receiver did not answer")
        if path == "/reset":
            return {"status": "reset", "cleared": True, "event_id": "a" * 32}
        return {"state_sha256": "b" * 64, "component": role, "pid": 123,
                "state": {} if role == "receiver" and failure == "bad_state"
                else auth.COMPONENT_INITIAL_STATE[role]}

    monkeypatch.setattr(auth, "component_request", fake_request)
    with pytest.raises(TimeoutError if failure == "timeout" else RuntimeError):
        state.reset_components("run", "case", "request")


def test_office_runner_verifies_target_completion_separately_from_receiver_acceptance():
    runner = TARGET_DIR.parent.parent / "experiments" / "gade-seven-level-v1" / "l3-action" / "Invoke-GadeL3D7D1Host.ps1"
    source = runner.read_text(encoding="utf-8-sig")
    assert "'lab.synthetic_receiver_transfer.v1'='l7_receiver_transfer_completed'" in source
    assert "'lab.synthetic_receiver_transfer.v1'='l7_receiver_accepted'" not in source
    assert "(Get-EventPropertyValue $_ 'event') -ceq 'l7_receiver_accepted'" in source




def receiver_response(digest):
    return {"status": "accepted", "receiver_id": "lab-receiver-fixed",
            "payload_sha256": digest, "state_sha256": "a" * 64, "event_id": "b" * 32}


def test_target_requires_complete_fixed_receiver_response():
    auth = load_module("l2_auth")
    digest = expected_digest()
    valid = receiver_response(digest)
    assert auth.valid_receiver_acceptance(valid, digest)
    for malformed in (
        {key: value for key, value in valid.items() if key != "event_id"},
        {**valid, "receiver_id": "unreviewed-receiver"},
        {**valid, "payload_sha256": "0" * 64},
        {**valid, "state_sha256": "bad"},
        {**valid, "event_id": "bad"},
        {**valid, "unexpected": True},
        None,
    ):
        assert not auth.valid_receiver_acceptance(malformed, digest)


def test_l7_target_fails_closed_before_transfer_event_on_bad_receiver_proof(monkeypatch, tmp_path):
    auth = load_module("l2_auth")
    password, reset_key = "p" * 32, "r" * 32
    state = auth.AuthState("lab-user", password, reset_key,
                           state_dir=tmp_path, enable_advanced=True)
    token = state.login("lab-user", password, "login-request", "case")
    assert state.perform_advanced("l7-collection", "0123456789ab", token,
                                  "collection-request", "case")["outcome"] == "completed"
    digest = expected_digest()
    response = receiver_response(digest)
    response.pop("event_id")
    monkeypatch.setattr(auth, "SEPARATE_COMPONENTS_REQUIRED", True)
    monkeypatch.setattr(auth, "COMPONENT_URLS", {**auth.COMPONENT_URLS,
                                                   "receiver": "http://receiver:8092"})
    monkeypatch.setattr(auth, "component_request", lambda *_args, **_kwargs: response)

    with pytest.raises(ValueError, match="fixed contract"):
        state.perform_advanced("l7-transfer", "0123456789ab", token,
                               "transfer-request", "case")

    assert "l7-transfer" not in state.advanced_state["completed_actions"]
    assert "transfer-request" not in state.advanced_state["completed_request_ids"]
    transfer_events = [row for row in state.events if row.get("request_id") == "transfer-request"]
    assert not any(row.get("event") in {"advanced_action_requested", "l7_receiver_accepted", "l7_receiver_transfer_completed"}
                   for row in transfer_events)
    assert state.event_context.failure_stage == "receiver_response_validation"


def test_l7_target_completes_only_after_fixed_receiver_acceptance(monkeypatch, tmp_path):
    auth = load_module("l2_auth")
    password, reset_key = "p" * 32, "r" * 32
    state = auth.AuthState("lab-user", password, reset_key,
                           state_dir=tmp_path, enable_advanced=True)
    token = state.login("lab-user", password, "login-request", "case")
    state.perform_advanced("l7-collection", "0123456789ab", token,
                           "collection-request", "case")
    # The office Windows test workspace denies delete-child on tmp_path, so
    # replace only the filesystem primitive here; container Live validation
    # exercises the real atomic replace on the Linux Target filesystem.
    def restricted_workspace_replace(source, destination):
        Path(destination).write_bytes(Path(source).read_bytes())
        Path(source).unlink()

    monkeypatch.setattr(auth.os, "replace", restricted_workspace_replace)
    seen = []

    def component(url, path, **kwargs):
        seen.append((url, path, kwargs))
        return receiver_response(expected_digest())

    monkeypatch.setattr(auth, "SEPARATE_COMPONENTS_REQUIRED", True)
    monkeypatch.setattr(auth, "COMPONENT_URLS", {**auth.COMPONENT_URLS,
                                                   "receiver": "http://receiver:8092"})
    monkeypatch.setattr(auth, "component_request", component)
    result = state.perform_advanced("l7-transfer", "0123456789ab", token,
                                    "transfer-request", "case")
    assert result["outcome"] == "completed"
    assert result["effect"]["receiver_event_id"] == "b" * 32
    assert result["effect"]["receiver_state_sha256"] == "a" * 64
    assert seen[0][1] == "/accept"
    assert seen[0][2]["timeout_seconds"] == 6.0
    assert seen[0][2]["deadline_monotonic"] is not None
    transfer_events = [row for row in state.events if row.get("request_id") == "transfer-request"]
    assert [row["event"] for row in transfer_events][-2:] == [
        "advanced_action_requested", "l7_receiver_transfer_completed"]
    receiver_event = {"event": "l7_receiver_accepted", "event_id": "b" * 32,
                      "run_id": "0123456789ab", "test_case_id": "case",
                      "request_id": "transfer-request", "state_sha256": "a" * 64}
    blue = load_module("blue_detection")
    alerts = blue.detect_advanced_synthetic(transfer_events, {"receiver": [receiver_event]})
    assert len(alerts) == 1
    assert alerts[0]["source_events"] == ["advanced_action_requested", "l7_receiver_transfer_completed"]
    unrelated_receiver = {**receiver_event, "event_id": "c" * 32}
    assert not blue.detect_advanced_synthetic(transfer_events, {"receiver": [unrelated_receiver]})


def test_receiver_acceptance_can_outlast_old_three_second_client_timeout(monkeypatch):
    """Reproduce accepted-before-response timeout; new bounded 6s budget succeeds."""
    auth = load_module("l2_auth")
    accepted = []
    accepted_event = Event()

    class DelayedReceiver(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            accepted.append(self.headers.get("X-Request-ID"))
            accepted_event.set()
            time.sleep(3.15)
            body = json.dumps(receiver_response(expected_digest())).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                # The first caller intentionally times out like the old code.
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), DelayedReceiver)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setitem(auth.COMPONENT_URLS, "receiver", base)
    body = {"record_ids": ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"],
            "payload_sha256": expected_digest()}
    try:
        with pytest.raises((TimeoutError, urllib.error.URLError)):
            auth.component_request(base, "/accept", method="POST", run_id="0123456789ab",
                case_id="case", request_id="old-timeout", body=body, timeout_seconds=3.0)
        assert accepted_event.wait(1.0), "Receiver did not record the old-timeout request before the client timeout"
        assert accepted == ["old-timeout"]
        deadline = time.monotonic() + auth.L7_TRANSFER_COMPONENT_BUDGET_SECONDS
        result = auth.component_request(base, "/accept", method="POST", run_id="0123456789ab",
            case_id="case", request_id="bounded-timeout", body=body,
            timeout_seconds=auth.L7_TRANSFER_COMPONENT_BUDGET_SECONDS,
            deadline_monotonic=deadline)
        assert auth.valid_receiver_acceptance(result, expected_digest())
        assert accepted == ["old-timeout", "bounded-timeout"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_receiver_rejects_duplicate_and_malformed_acceptance(monkeypatch, tmp_path):
    monkeypatch.setenv("GADE_COMPONENT_ROLE", "receiver")
    component = load_module("synthetic_component")
    monkeypatch.setattr(component, "ROLE", "receiver")
    monkeypatch.setattr(component, "COMPONENT_API_KEY", "k" * 48)
    monkeypatch.setattr(component, "BLUE_OBSERVER_KEY", "b" * 48)
    monkeypatch.setattr(component, "STATE_DIR", tmp_path)
    monkeypatch.setattr(component, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(component, "LOG_PATH", tmp_path / "events.jsonl")
    published = []
    monkeypatch.setattr(component, "publish", lambda event: published.append(event))
    server = ThreadingHTTPServer(("127.0.0.1", 0), component.Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/accept"
    digest = expected_digest()
    headers = {"Content-Type": "application/json", "X-GADE-Component-Key": "k" * 48,
               "X-Run-ID": "0123456789ab", "X-Test-Case-ID": "case",
               "X-Request-ID": "receiver-request"}

    def send(payload, request_headers=headers):
        request = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                         headers=request_headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        malformed_status, malformed = send({"record_ids": ["wrong"], "payload_sha256": digest})
        assert malformed_status == 400 and malformed["error"] == "fixed_synthetic_records_required"
        status, first = send({"record_ids": ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"],
                              "payload_sha256": digest})
        assert status == 200 and first["status"] == "accepted"
        duplicate_status, duplicate = send(
            {"record_ids": ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"],
             "payload_sha256": digest})
        assert duplicate_status == 409 and duplicate["error"] == "request_already_executed"
        state = component.load_state()
        assert state["accepted_payloads"] == [digest]
        assert len(published) == 1 and published[0]["event"] == "l7_receiver_accepted"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

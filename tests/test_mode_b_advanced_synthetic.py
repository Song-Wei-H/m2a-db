"""Offline fixed synthetic L5-L7 state, evidence, reset, and detection tests."""

import importlib.util
import secrets
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1] / "lab" / "mode-b-target"


def load(name):
    spec = importlib.util.spec_from_file_location(f"advanced_{name}", ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


auth = load("l2_auth")
blue = load("blue_detection")


def test_advanced_actions_are_disabled_by_default(tmp_path):
    state = auth.AuthState("lab-user", secrets.token_urlsafe(32), secrets.token_urlsafe(32),
                           state_dir=tmp_path)
    with pytest.raises(ValueError):
        state.perform_advanced("l5-canary", "run", "", "req", "case")
    assert not state.advanced_state_path.exists()


def test_all_fixed_advanced_effects_have_distinct_state_events_alerts_and_reset(tmp_path):
    password, reset_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    state = auth.AuthState("lab-user", password, reset_key, state_dir=tmp_path,
                           enable_advanced=True)
    token = state.login("lab-user", password, "login", "case")
    assert token
    actions = ["l5-canary", "l5-visibility", "l6-discovery", "l6-session",
               "l7-collection", "l7-c2", "l7-transfer", "l7-impact"]
    for index, action in enumerate(actions, 1):
        request = f"req-{index}"
        result = state.perform_advanced(action, "run", token, request, "case")
        assert result["outcome"] == "completed" and result["simulation"] is True
        assert len(result["state_sha256"]) == 64
        proof = state.inspect_advanced("run", "case", request)
        alerts = blue.detect_advanced_synthetic(proof["events"], proof["node_events"])
        assert len(alerts) == 1 and alerts[0]["action"] == action
        assert alerts[0]["detection_mode"] == "OFFLINE_REPLAY"
        assert blue.detect_advanced_synthetic(proof["events"][:1], proof["node_events"]) == []
        with pytest.raises(RuntimeError):
            state.perform_advanced(action, "run", token, request, "case")
        with pytest.raises(RuntimeError):
            state.perform_advanced(action, "run", token, f"retry-{index}", "case")
    assert state.advanced_state["canary_accessed"] is True
    assert state.advanced_state["visibility_mode"] == "simulated_degraded_visibility"
    assert state.advanced_state["node_session_active"] is True
    assert state.node_log_paths["node-alpha"].is_file()
    assert state.node_log_paths["node-beta"].is_file()
    assert state.advanced_state["receiver_digest"]
    assert state.advanced_state["impact_mode"] == "simulated_interruption"
    restarted = auth.AuthState("lab-user", password, reset_key, state_dir=tmp_path,
                               enable_advanced=True)
    assert restarted.advanced_state["node_session_active"] is True
    assert restarted.reset(reset_key, "reset", "case") is True
    assert restarted.advanced_state == auth.ADVANCED_INITIAL
    assert not restarted.advanced_state_path.exists()
    assert all(not path.exists() for path in restarted.node_log_paths.values())


def test_advanced_preconditions_and_detection_fail_closed(tmp_path):
    password, reset_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    state = auth.AuthState("lab-user", password, reset_key, state_dir=tmp_path,
                           enable_advanced=True)
    token = state.login("lab-user", password, "login", "case")
    assert state.perform_advanced("l6-session", "run", token, "req-s", "case")["outcome"] == "precondition_missing"
    assert state.perform_advanced("l7-transfer", "run", token, "req-t", "case")["outcome"] == "precondition_missing"
    assert not state.advanced_state_path.exists()
    assert state.perform_advanced("l6-discovery", "run", token, "req-d", "case")["outcome"] == "completed"
    state.perform_advanced("l6-session", "run", token, "req-s", "case")
    proof = state.inspect_advanced("run", "case", "req-s")
    assert blue.detect_advanced_synthetic(proof["events"], {"node-alpha": [], "node-beta": []}) == []
    assert blue.detect_advanced_synthetic(proof["events"],
        {"node-alpha": proof["node_events"]["node-alpha"], "node-beta": []}) == []

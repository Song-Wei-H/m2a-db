from __future__ import annotations

import contextlib
import io
import importlib.util
from pathlib import Path
import secrets
import time

MODULE_PATH = Path(__file__).parents[1] / "lab/mode-b-target/l2_auth.py"
SPEC = importlib.util.spec_from_file_location("mode_b_l2_auth", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)
AuthState = MODULE.AuthState


def test_login_session_protects_resource_and_logs_no_secrets():
    username = "unit-l2-user"
    password = secrets.token_urlsafe(32)
    reset_key = secrets.token_urlsafe(32)
    state = AuthState(username, password, reset_key, ttl=60)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert state.authorize("", "req-no-session", "L2-NO-SESSION") is False
        assert state.login(username, "wrong", "req-wrong", "L2-WRONG") is None
        token = state.login(username, password, "req-good", "L2-GOOD")
        assert token
        assert state.authorize(token, "req-access", "L2-ACCESS") is True
        assert state.reset(reset_key, "req-reset", "L2-RESET") is True
        assert state.authorize(token, "req-invalidated", "L2-INVALIDATED") is False
    logs = output.getvalue()
    assert password not in logs and reset_key not in logs and token not in logs
    assert "login_succeeded" in logs and "login_rejected" in logs
    assert "session_created" in logs and "protected_access_granted" in logs
    assert "protected_access_denied" in logs and "state_reset" in logs


def test_expired_session_is_denied_and_not_reusable():
    state = AuthState("unit-l2-user", secrets.token_urlsafe(32), secrets.token_urlsafe(32), ttl=60)
    token = state.login(state.username, state._password.decode(), "req-login", "L2-EXPIRY")
    assert token
    state.sessions[state.token_hash(token)] = (time.monotonic() - 1, state.username)
    assert state.authorize(token, "req-expired", "L2-EXPIRY") is False
    assert state.token_hash(token) not in state.sessions

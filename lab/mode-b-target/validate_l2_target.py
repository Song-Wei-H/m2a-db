"""One-run black-box validation for the isolated T1078 test target.

The local .env file is read only in memory. It is never copied to evidence or
included in output. Session tokens and passwords are excluded from all records.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"GADE_L2_[A-Z0-9_]+", key):
            raise ValueError("invalid local test configuration format")
        values[key] = value
    return values


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Client:
    def __init__(self, base: str, run_id: str):
        self.base = base.rstrip("/")
        self.run_id = run_id
        self.records: list[dict] = []
        self.n = 0

    def call(self, case: str, method: str, path: str, *, body: dict | None = None,
             token: str | None = None) -> tuple[int, dict]:
        self.n += 1
        request_id = str(uuid.uuid4())
        headers = {"X-Request-ID": request_id, "X-Test-Case-ID": f"{self.run_id}-{case}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, separators=(",", ":")).encode()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        status = 0
        payload: dict = {}
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                status = response.status
                raw = response.read(8192)
        except urllib.error.HTTPError as error:
            status = error.code
            raw = error.read(8192)
        try:
            payload = json.loads(raw) if raw else {}
            if not isinstance(payload, dict):
                payload = {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {"text_sha256": hashlib.sha256(raw).hexdigest(),
                       "text_contains_target_title": b"M2A Mode B Lab Target" in raw,
                       "text_is_original_health_body": raw.strip() == b"mode-b-target-ready"}
        safe = {key: value for key, value in payload.items() if key != "session_token"}
        self.records.append({"time_utc": utc_now(), "request_id": request_id,
                             "test_case_id": headers["X-Test-Case-ID"], "method": method,
                             "path": path, "http_status": status, "response_safe": safe})
        return status, payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://10.56.66.119:18080")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cfg = load_env(args.config)
    user = cfg["GADE_L2_TEST_USERNAME"]
    password = cfg["GADE_L2_TEST_PASSWORD"]
    reset_key = cfg["GADE_L2_RESET_KEY"]
    client = Client(args.target, args.run_id)
    checks: dict[str, str] = {}

    def expect(name: str, got: int, wanted: int) -> None:
        checks[name] = "PASS" if got == wanted else f"FAIL expected_http_{wanted}_got_{got}"
        if got != wanted:
            raise RuntimeError(checks[name])

    status, _ = client.call("reset-initial", "POST", "/lab/admin/reset", body={"reset_key": reset_key})
    expect("initial_reset", status, 200)
    status, _ = client.call("no-session", "GET", "/lab/protected")
    expect("no_session_denied", status, 401)
    status, _ = client.call("invalid-session", "GET", "/lab/protected", token="invalid-session-not-a-secret")
    expect("invalid_session_denied", status, 401)
    status, _ = client.call("wrong-credentials", "POST", "/lab/auth/login",
                            body={"username": user, "password": "wrong-credential-test-only"})
    expect("wrong_credentials_denied", status, 401)
    status, login = client.call("login-cycle-1", "POST", "/lab/auth/login",
                                body={"username": user, "password": password})
    expect("valid_login", status, 200)
    token = login.get("session_token")
    if not isinstance(token, str) or len(token) < 32:
        raise RuntimeError("valid login did not return a session")
    status, protected = client.call("protected-cycle-1", "GET", "/lab/protected", token=token)
    expect("protected_resource_with_session", status, 200)
    checks["protected_resource_content"] = (
        "PASS" if protected.get("resource") == "lab-only-protected-resource"
        and protected.get("scenario") == "T1078-test-account" else "FAIL"
    )
    if checks["protected_resource_content"] != "PASS":
        raise RuntimeError("protected resource response mismatch")

    status, _ = client.call("reset-cycle-1", "POST", "/lab/admin/reset", body={"reset_key": reset_key})
    expect("reset_invalidates_session", status, 200)
    status, _ = client.call("old-session-after-reset", "GET", "/lab/protected", token=token)
    expect("old_session_denied_after_reset", status, 401)
    status, login2 = client.call("login-cycle-2", "POST", "/lab/auth/login",
                                 body={"username": user, "password": password})
    expect("repeat_login", status, 200)
    token2 = login2.get("session_token")
    status, protected2 = client.call("protected-cycle-2", "GET", "/lab/protected", token=token2)
    expect("repeat_protected_access", status, 200)
    if protected2.get("resource") != "lab-only-protected-resource":
        raise RuntimeError("repeat protected resource response mismatch")
    status, _ = client.call("reset-final", "POST", "/lab/admin/reset", body={"reset_key": reset_key})
    expect("final_reset", status, 200)

    # Verify the original static L1 target remains available and unchanged at its
    # canonical route. This is target regression, not a GADE Worker E2E replay.
    status, health = client.call("l1-healthz", "GET", "/healthz")
    expect("l1_healthz", status, 200)
    checks["l1_healthz_body_unchanged"] = "PASS" if health.get("text_is_original_health_body") else "FAIL"
    if checks["l1_healthz_body_unchanged"] != "PASS":
        raise RuntimeError("original L1 health response body changed")
    status, root = client.call("l1-root", "GET", "/")
    expect("l1_root", status, 200)
    checks["l1_static_content"] = "PASS" if root.get("text_contains_target_title") else "FAIL"

    if any(value != "PASS" and value != "PASS_HTTP_200" for value in checks.values()):
        raise RuntimeError("one or more test checks failed")
    document = {
        "run_id": args.run_id,
        "scenario_id": "GADE-L2-T1078-VALID-ACCOUNT-001",
        "started_utc": client.records[0]["time_utc"],
        "completed_utc": utc_now(),
        "target": args.target,
        "technique": "MITRE ATT&CK T1078 Valid Accounts",
        "gade_depth": 2,
        "credential_values_recorded": False,
        "session_token_recorded": False,
        "session_ttl_seconds": int(cfg.get("GADE_L2_SESSION_TTL_SECONDS", "60")),
        "checks": checks,
        "requests": client.records,
        "result": "PASS",
    }
    rendered = json.dumps(document, ensure_ascii=False)
    if password in rendered or reset_key in rendered or token in rendered or token2 in rendered:
        raise RuntimeError("evidence unexpectedly contains a secret")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"L2_TARGET_VALIDATION=PASS RUN_ID={args.run_id} REQUESTS={len(client.records)} EVIDENCE={args.output}")


if __name__ == "__main__":
    main()

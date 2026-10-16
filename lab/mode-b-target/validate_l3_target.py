"""One-run live validation for the isolated L3 controlled-execution lab scenario."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_TARGET = "http://10.56.66.119:18080"
SCRIPT_ID = "gade-controlled-python-execution-v1"
SCRIPT_PATH = Path(__file__).with_name("l3_execution_task.py")
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
EFFECTIVE_SESSION_TTL_SECONDS = 60  # compose.mode-b-target.yml overrides the env file to 60.


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"GADE_L2_[A-Z0-9_]+", key):
            raise ValueError("invalid local test configuration format")
        values[key] = value.strip().strip('"').strip("'")
    required = ("GADE_L2_TEST_USERNAME", "GADE_L2_TEST_PASSWORD", "GADE_L2_RESET_KEY")
    if any(not values.get(name) for name in required):
        raise ValueError("required local lab settings are missing")
    return values


class Client:
    def __init__(self, target: str, run_id: str, output: Path):
        self.target = target.rstrip("/")
        self.run_id = run_id
        self.output = output
        self.records: list[dict] = []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def save(self, state: str, checks: dict, started: str) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "run_id": self.run_id,
            "scenario_id": "GADE-L3-T1059.006-CONTROLLED-EXECUTION-001",
            "classification": "controlled execution emulation; not arbitrary code execution exploitation",
            "technique": "MITRE ATT&CK T1059.006 Python",
            "gade_depth": 3,
            "target": self.target,
            "script_id": SCRIPT_ID,
            "script_sha256": hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest(),
            "started_utc": started,
            "updated_utc": utc_now(),
            "checks": checks,
            "requests": self.records,
            "result": state,
            "secrets_recorded": False,
        }
        # Use a unique sibling so concurrent readers/runs cannot collide. Windows
        # scanners may briefly hold a freshly-written JSON file without delete
        # sharing; retry only that atomic replacement, keeping the last complete
        # checkpoint intact until replacement succeeds.
        temporary = self.output.with_name(
            f"{self.output.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        payload = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            last_error: PermissionError | None = None
            for attempt in range(8):
                try:
                    os.replace(temporary, self.output)
                    return
                except PermissionError as error:
                    last_error = error
                    if attempt < 7:
                        time.sleep(0.25 * (attempt + 1))
            raise OSError(
                f"could not atomically replace validation evidence after 8 attempts; "
                f"complete checkpoint preserved at {temporary}"
            ) from last_error
        except Exception:
            # Do not remove a complete temp checkpoint after a persistent lock;
            # it is the recoverable copy if the prior destination remains locked.
            raise

    def call(self, case: str, method: str, path: str, *, body: dict | None = None,
             token: str | None = None, reset_key: str | None = None):
        request_id = str(uuid.uuid4())
        case_id = f"{self.run_id}-{case}"
        headers = {"X-Request-ID": request_id, "X-Test-Case-ID": case_id,
                   "X-Run-ID": self.run_id}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if reset_key is not None:
            headers["X-Lab-Reset-Key"] = reset_key
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(self.target + path, data=data, headers=headers, method=method)
        status, raw = 0, b""
        try:
            with self.opener.open(request, timeout=8) as response:
                status, raw = response.status, response.read(65536)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read(65536)
        except Exception as error:
            self.records.append({"time_utc": utc_now(), "request_id": request_id,
                                 "test_case_id": case_id, "method": method, "path": path,
                                 "transport_error": type(error).__name__})
            raise
        try:
            payload = json.loads(raw) if raw else {}
            if not isinstance(payload, dict):
                payload = {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {"body_sha256": hashlib.sha256(raw).hexdigest(),
                       "l1_health_body": raw.strip() == b"mode-b-target-ready",
                       "l1_title_present": b"M2A Mode B Lab Target" in raw}
        safe_payload = dict(payload)
        safe_payload.pop("session_token", None)
        record = {"time_utc": utc_now(), "request_id": request_id,
                  "test_case_id": case_id, "method": method, "path": path,
                  "http_status": status, "response_safe": safe_payload}
        self.records.append(record)
        return status, payload, record

    def inspect(self, case: str, request_record: dict, reset_key: str):
        query = urllib.parse.urlencode({"run_id": self.run_id,
                                        "case_id": request_record["test_case_id"],
                                        "request_id": request_record["request_id"]})
        return self.call(case, "GET", "/lab/admin/l3-evidence?" + query,
                         reset_key=reset_key)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=EXPECTED_TARGET)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.target.rstrip("/") != EXPECTED_TARGET:
        raise SystemExit("refusing non-canonical isolated lab target")
    if not ID_RE.fullmatch(args.run_id):
        raise SystemExit("invalid run id")
    cfg = load_env(args.config)
    ttl = EFFECTIVE_SESSION_TTL_SECONDS
    target_script_sha = hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
    client = Client(args.target.rstrip("/"), args.run_id, args.output)
    checks: dict[str, str] = {}
    started = utc_now()

    def require(name: str, condition: bool, explanation: str) -> None:
        checks[name] = "PASS" if condition else "FAIL"
        client.save("RUNNING" if condition else "FAIL", checks, started)
        if not condition:
            raise RuntimeError(f"{name}: {explanation}")

    try:
        status, reset, _ = client.call("reset-initial", "POST", "/lab/admin/reset",
                                       body={"reset_key": cfg["GADE_L2_RESET_KEY"]},
                                       reset_key=cfg["GADE_L2_RESET_KEY"])
        require("initial_reset_verified", status == 200 and reset.get("status") == "reset"
                and reset.get("active_sessions") == 0 and reset.get("l3_marker_cleared") is True
                and reset.get("l3_temp_files_cleared") is True,
                "target did not confirm a clean state")

        for case, supplied_token in (("no-session", None), ("invalid-session", "invalid-l3-session")):
            status, _, request_record = client.call(case, "POST", "/lab/execute", body={},
                                                    token=supplied_token)
            require(f"{case}_denied", status == 401, "execution request was not denied")
            inspect_status, proof, _ = client.inspect(f"inspect-{case}", request_record,
                                                       cfg["GADE_L2_RESET_KEY"])
            events = {event.get("event") for event in proof.get("events", [])}
            require(f"{case}_no_execution_effect", inspect_status == 200
                    and proof.get("marker_present") is False and proof.get("execution") is None
                    and "protected_access_denied" in events
                    and "l3_process_started" not in events,
                    "unauthorized request left execution state")

        login_status, login, _ = client.call("login-first", "POST", "/lab/auth/login",
                                             body={"username": cfg["GADE_L2_TEST_USERNAME"],
                                                   "password": cfg["GADE_L2_TEST_PASSWORD"]})
        token = login.get("session_token")
        require("valid_session_issued", login_status == 200 and isinstance(token, str) and len(token) >= 32,
                "target did not issue a valid session")

        execute_status, execution, exec_record = client.call("execute-first", "POST", "/lab/execute",
                                                              body={}, token=token)
        require("fixed_process_execution", execute_status == 200
                and execution.get("status") == "completed" and execution.get("exit_status") == 0
                and execution.get("script_id") == SCRIPT_ID
                and execution.get("script_sha256") == target_script_sha,
                "target did not report the expected fixed process execution")
        inspect_status, proof, _ = client.inspect("inspect-first", exec_record, cfg["GADE_L2_RESET_KEY"])
        marker = proof.get("marker") or {}
        execution_record = proof.get("execution") or {}
        events = {event.get("event") for event in proof.get("events", [])}
        require("independent_target_marker_and_events", inspect_status == 200
                and proof.get("marker_present") is True
                and proof.get("marker_sha256") == execution.get("marker_sha256")
                and marker.get("script_id") == SCRIPT_ID
                and marker.get("script_sha256") == target_script_sha
                and marker.get("run_id") == args.run_id
                and marker.get("test_case_id") == exec_record["test_case_id"]
                and marker.get("request_id") == exec_record["request_id"]
                and marker.get("result") == 39
                and marker.get("marker") == "GADE-L3-CONTROLLED-EXECUTION-COMPLETE"
                and bool(marker.get("executed_at_utc"))
                and execution_record.get("started_utc") and execution_record.get("completed_utc")
                and execution_record.get("exit_status") == 0
                and execution_record.get("outcome") == "completed"
                and {"protected_access_granted", "l3_process_started", "l3_execution_completed"}.issubset(events),
                "independent target inspection did not match the execution request")

        reset_status, reset, _ = client.call("reset-after-first", "POST", "/lab/admin/reset",
                                              body={"reset_key": cfg["GADE_L2_RESET_KEY"]},
                                              reset_key=cfg["GADE_L2_RESET_KEY"])
        require("reset_cleared_marker_and_sessions", reset_status == 200
                and reset.get("status") == "reset" and reset.get("active_sessions") == 0
                and reset.get("l3_marker_cleared") is True and reset.get("l3_temp_files_cleared") is True,
                "reset did not prove marker/session clearance")
        old_status, _, old_request = client.call("old-session-after-reset", "POST", "/lab/execute",
                                                  body={}, token=token)
        require("reset_invalidated_old_session", old_status == 401,
                "old session remained usable after reset")
        inspect_status, proof, _ = client.inspect("inspect-after-reset", old_request,
                                                   cfg["GADE_L2_RESET_KEY"])
        require("reset_old_session_no_effect", inspect_status == 200
                and proof.get("marker_present") is False and proof.get("execution") is None,
                "old session created an execution result after reset")

        login_status, login2, _ = client.call("login-repeat", "POST", "/lab/auth/login",
                                               body={"username": cfg["GADE_L2_TEST_USERNAME"],
                                                     "password": cfg["GADE_L2_TEST_PASSWORD"]})
        token2 = login2.get("session_token")
        require("repeat_session_issued", login_status == 200 and isinstance(token2, str),
                "repeat test could not obtain a session")
        repeat_status, repeat, repeat_record = client.call("execute-repeat", "POST", "/lab/execute",
                                                           body={}, token=token2)
        repeat_inspect_status, repeat_proof, _ = client.inspect("inspect-repeat", repeat_record,
                                                                 cfg["GADE_L2_RESET_KEY"])
        repeat_marker = repeat_proof.get("marker") or {}
        require("repeat_execution_reproduced", repeat_status == 200 and repeat_inspect_status == 200
                and repeat_marker.get("result") == marker.get("result") == 39
                and repeat_marker.get("script_id") == marker.get("script_id") == SCRIPT_ID
                and repeat_marker.get("script_sha256") == marker.get("script_sha256") == target_script_sha,
                "repeat run did not reproduce the fixed execution effect")

        reset_status, reset, _ = client.call("reset-before-expiry", "POST", "/lab/admin/reset",
                                              body={"reset_key": cfg["GADE_L2_RESET_KEY"]},
                                              reset_key=cfg["GADE_L2_RESET_KEY"])
        require("reset_before_expiry", reset_status == 200 and reset.get("l3_marker_cleared") is True
                and reset.get("l3_temp_files_cleared") is True,
                "could not reset before expiry test")
        expiry_status, expiry_login, _ = client.call("login-expiry", "POST", "/lab/auth/login",
                                                      body={"username": cfg["GADE_L2_TEST_USERNAME"],
                                                            "password": cfg["GADE_L2_TEST_PASSWORD"]})
        expiry_token = expiry_login.get("session_token")
        require("expiry_session_issued", expiry_status == 200 and isinstance(expiry_token, str),
                "could not issue expiry-test session")
        checks["expiry_wait_seconds"] = str(ttl + 1)
        client.save("RUNNING", checks, started)
        time.sleep(ttl + 1)
        expired_status, _, expired_request = client.call("expired-session", "POST", "/lab/execute",
                                                          body={}, token=expiry_token)
        require("expired_session_denied", expired_status == 401,
                "expired session was not denied")
        inspect_status, proof, _ = client.inspect("inspect-expired", expired_request,
                                                   cfg["GADE_L2_RESET_KEY"])
        require("expired_session_no_effect", inspect_status == 200
                and proof.get("marker_present") is False and proof.get("execution") is None,
                "expired session left an execution effect")

        status, health, _ = client.call("l1-health", "GET", "/healthz")
        require("l1_health_regression", status == 200 and health.get("l1_health_body") is True,
                "L1 health response changed")
        status, root, _ = client.call("l1-static-root", "GET", "/")
        require("l1_static_regression", status == 200 and root.get("l1_title_present") is True,
                "L1 static target page changed")
        l2_status, l2_login, _ = client.call("l2-login-regression", "POST", "/lab/auth/login",
                                             body={"username": cfg["GADE_L2_TEST_USERNAME"],
                                                   "password": cfg["GADE_L2_TEST_PASSWORD"]})
        l2_token = l2_login.get("session_token")
        require("l2_login_regression", l2_status == 200 and isinstance(l2_token, str),
                "L2 login behavior regressed")
        l2_status, l2_body, _ = client.call("l2-protected-regression", "GET", "/lab/protected",
                                             token=l2_token)
        require("l2_protected_regression", l2_status == 200
                and l2_body.get("access") == "granted"
                and l2_body.get("resource") == "lab-only-protected-resource",
                "L2 protected resource behavior regressed")
        final_status, final_reset, _ = client.call("reset-final", "POST", "/lab/admin/reset",
                                                    body={"reset_key": cfg["GADE_L2_RESET_KEY"]},
                                                    reset_key=cfg["GADE_L2_RESET_KEY"])
        require("final_clean_state", final_status == 200 and final_reset.get("l3_marker_cleared") is True
                and final_reset.get("l3_temp_files_cleared") is True and final_reset.get("active_sessions") == 0,
                "final target state could not be reset")
        client.save("PASS", checks, started)
        print(f"L3_TARGET_VALIDATION=PASS RUN_ID={args.run_id} CHECKS={len(checks)} EVIDENCE={args.output}")
    except Exception as error:
        # Leave the shared lab in a known clean state even if a later assertion
        # or evidence write fails. Record the cleanup result without hiding the
        # original validation exception.
        cleanup = {"status": "not_attempted"}
        try:
            reset_status, reset_body, reset_record = client.call(
                "failure-cleanup-reset", "POST", "/lab/admin/reset",
                body={"reset_key": cfg["GADE_L2_RESET_KEY"]},
                reset_key=cfg["GADE_L2_RESET_KEY"],
            )
            cleanup = {
                "status": "verified" if reset_status == 200
                and reset_body.get("status") == "reset"
                and reset_body.get("active_sessions") == 0
                and reset_body.get("l3_marker_cleared") is True
                and reset_body.get("l3_temp_files_cleared") is True else "failed",
                "http_status": reset_status,
                "request_id": reset_record.get("request_id"),
                "test_case_id": reset_record.get("test_case_id"),
                "response_safe": reset_record.get("response_safe"),
            }
        except Exception as cleanup_error:
            cleanup = {"status": "failed", "error_type": type(cleanup_error).__name__}
        failure_checks = {
            **checks,
            "failure": type(error).__name__,
            "failure_message": str(error),
            "failure_cleanup_reset": cleanup,
        }
        try:
            client.save("FAIL", failure_checks, started)
        except Exception as evidence_error:
            raise RuntimeError(
                f"validation failed ({type(error).__name__}); failure evidence save also failed "
                f"({type(evidence_error).__name__}): {evidence_error}"
            ) from error
        raise


if __name__ == "__main__":
    main()

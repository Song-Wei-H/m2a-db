"""Separate, fixed synthetic node/receiver processes for the office Docker lab."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None

ROLE = os.environ.get("GADE_COMPONENT_ROLE", "")
if ROLE not in {"node-alpha", "node-beta", "receiver"}:
    raise RuntimeError("invalid fixed synthetic component role")
BLUE_URL = os.environ.get("GADE_BLUE_OBSERVER_URL", "http://blue-observer:8090/ingest")
COMPONENT_API_KEY = os.environ.get("GADE_COMPONENT_API_KEY", "")
BLUE_OBSERVER_KEY = os.environ.get("GADE_BLUE_OBSERVER_KEY", "")
STATE_DIR = Path(os.environ.get("GADE_COMPONENT_STATE_DIR", "/tmp/gade-component"))
STATE_PATH = STATE_DIR / "state.json"
LOG_PATH = STATE_DIR / "events.jsonl"
LOCK = threading.RLock()
MAX_BODY = 2048
RECORD_IDS = ["SYNTHETIC-RECORD-1", "SYNTHETIC-RECORD-2"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def session_id(run_id: str, case_id: str, request_id: str) -> str:
    return hashlib.sha256(f"gade-synthetic-session-v1:{run_id}:{case_id}:{request_id}".encode()).hexdigest()


def initial_state() -> dict[str, Any]:
    if ROLE == "node-alpha":
        return {"node_id": ROLE, "opened_sessions": [], "completed_requests": []}
    if ROLE == "node-beta":
        return {"node_id": ROLE, "accepted_sessions": [], "completed_requests": []}
    return {"receiver_id": "lab-receiver-fixed", "accepted_payloads": [], "completed_requests": []}


def load_state() -> dict[str, Any]:
    if not STATE_PATH.is_file():
        return initial_state()
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    expected = initial_state()
    identity = state.get("node_id", state.get("receiver_id")) if isinstance(state, dict) else None
    if identity != expected.get("node_id", expected.get("receiver_id")):
        raise RuntimeError("synthetic component state identity mismatch")
    return state


def save_state(state: dict[str, Any]) -> str:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temp = STATE_PATH.with_name(f".state.{uuid4().hex}.tmp")
    temp.write_bytes(encoded)
    os.replace(temp, STATE_PATH)
    return hashlib.sha256(encoded).hexdigest()


def publish(event: dict[str, Any]) -> None:
    if BLUE_URL != "http://blue-observer:8090/ingest" or len(BLUE_OBSERVER_KEY) < 32:
        raise RuntimeError("fixed isolated Blue Observer configuration is incomplete")
    payload = json.dumps({"source": ROLE, "event": event}, sort_keys=True, separators=(",", ":")).encode()
    request = urllib.request.Request(BLUE_URL, data=payload, headers={
        "Content-Type": "application/json", "X-GADE-Observer-Key": BLUE_OBSERVER_KEY,
    }, method="POST")
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=2) as response:
        import json as json_module
        ack = json_module.loads(response.read(4096))
        if response.status != 202 or ack.get("accepted") is not True:
            raise RuntimeError("independent Blue Observer did not accept component event")


def emit(event_name: str, run_id: str, case_id: str, request_id: str, **fields: Any) -> dict[str, Any]:
    event = {"event_id": uuid4().hex, "time_utc": utc_now(), "event": event_name,
             "run_id": run_id, "test_case_id": case_id, "request_id": request_id,
             "component": ROLE, "simulation": True, **fields}
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    publish(event)
    print(json.dumps({"type": "target_event", **event}, sort_keys=True), flush=True)
    return event


class Handler(BaseHTTPRequestHandler):
    server_version = "GADE-Synthetic-Component"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def reply(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def identity(self) -> tuple[str, str, str] | None:
        run_id = self.headers.get("X-Run-ID", "")
        case_id = self.headers.get("X-Test-Case-ID", "")
        request_id = self.headers.get("X-Request-ID", "")
        valid = lambda item: bool(item) and len(item) <= 96 and all(ch.isalnum() or ch in "_.:-" for ch in item)
        return (run_id, case_id, request_id) if all(map(valid, (run_id, case_id, request_id))) else None

    def authorized(self) -> bool:
        return bool(COMPONENT_API_KEY) and hmac.compare_digest(
            self.headers.get("X-GADE-Component-Key", "").encode(), COMPONENT_API_KEY.encode())

    def body(self) -> dict[str, Any] | None:
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BODY or self.headers.get_content_type() != "application/json":
                return None
            value = json.loads(self.rfile.read(size))
            return value if isinstance(value, dict) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self.reply(200, {"status": "ok", "component": ROLE, "pid": os.getpid()})
            return
        if urlsplit(self.path).path == "/snapshot":
            if not self.authorized():
                self.reply(403, {"error": "component_authentication_required"})
                return
            query = parse_qs(urlsplit(self.path).query)
            run_id, case_id, request_id = (query.get(key, [""])[0]
                                           for key in ("run_id", "case_id", "request_id"))
            with LOCK:
                state = load_state()
                state_bytes = (STATE_PATH.read_bytes() if STATE_PATH.is_file()
                               else json.dumps(state, sort_keys=True, separators=(",", ":")).encode())
                rows = ([json.loads(line) for line in LOG_PATH.read_text(encoding="utf-8").splitlines()]
                        if LOG_PATH.is_file() else [])
            selected = ([row for row in rows if all(row.get(key) == value for key, value in (
                ("run_id", run_id), ("test_case_id", case_id), ("request_id", request_id)))]
                if run_id and case_id and request_id else [])
            self.reply(200, {"component": ROLE, "pid": os.getpid(), "state": state,
                             "state_sha256": hashlib.sha256(state_bytes).hexdigest(),
                             "events": selected})
            return
        if ROLE not in {"node-alpha", "node-beta"} or self.path != "/identity":
            self.reply(404, {"error": "not_found"})
            return
        if not self.authorized():
            self.reply(403, {"error": "component_authentication_required"})
            return
        identity = self.identity()
        if identity is None:
            self.reply(400, {"error": "identity_required"})
            return
        run_id, case_id, request_id = identity
        with LOCK:
            state = load_state()
            if request_id in state["completed_requests"]:
                self.reply(409, {"error": "request_already_seen"})
                return
            state["completed_requests"].append(request_id)
            state_sha = save_state(state)
            event = emit("l6_node_identity_observed", run_id, case_id, request_id,
                         node_id=ROLE, state_sha256=state_sha, component_state_sha256=state_sha)
        self.reply(200, {"node_id": ROLE, "event_id": event["event_id"], "state_sha256": state_sha})

    def do_POST(self) -> None:  # noqa: N802
        if not self.authorized():
            self.reply(403, {"error": "component_authentication_required"})
            return
        identity = self.identity()
        body = self.body()
        if identity is None or body is None:
            self.reply(400, {"error": "fixed_identity_and_json_required"})
            return
        run_id, case_id, request_id = identity
        with LOCK:
            state = load_state()
            if self.path == "/reset":
                if set(body) != {"reset"} or body.get("reset") is not True:
                    self.reply(400, {"error": "fixed_reset_required"})
                    return
                state = initial_state()
                state_sha = save_state(state)
                event = emit("component_state_reset", run_id, case_id, request_id, state_sha256=state_sha)
                self.reply(200, {"status": "reset", "cleared": True,
                                 "state_sha256": state_sha, "event_id": event["event_id"]})
                return
            if ROLE == "node-alpha" and self.path == "/session/open":
                if set(body) != {"purpose"} or body.get("purpose") != "fixed-synthetic-session-v1":
                    self.reply(400, {"error": "fixed_session_contract_required"})
                    return
                if request_id in state["completed_requests"]:
                    self.reply(409, {"error": "request_already_executed"})
                    return
                sid = session_id(run_id, case_id, request_id)
                state["opened_sessions"].append(sid)
                state["completed_requests"].append(request_id)
                state_sha = save_state(state)
                event = emit("l6_source_session_opened", run_id, case_id, request_id,
                             node_id=ROLE, session_id_sha256=sid, state_sha256=state_sha,
                             component_state_sha256=state_sha)
                self.reply(200, {"status": "opened", "session_id": sid,
                                 "state_sha256": state_sha, "event_id": event["event_id"]})
                return
            if ROLE == "node-beta" and self.path == "/session/accept":
                if set(body) != {"session_id"} or body.get("session_id") != session_id(run_id, case_id, request_id):
                    self.reply(403, {"error": "synthetic_session_identity_mismatch"})
                    return
                if request_id in state["completed_requests"]:
                    self.reply(409, {"error": "request_already_executed"})
                    return
                state["accepted_sessions"].append(body["session_id"])
                state["completed_requests"].append(request_id)
                state_sha = save_state(state)
                event = emit("l6_destination_session_accepted", run_id, case_id, request_id,
                             node_id=ROLE, session_id_sha256=body["session_id"], state_sha256=state_sha,
                             component_state_sha256=state_sha)
                self.reply(200, {"status": "accepted", "state_sha256": state_sha,
                                 "event_id": event["event_id"]})
                return
            if ROLE == "receiver" and self.path == "/accept":
                if set(body) != {"record_ids", "payload_sha256"} or body.get("record_ids") != RECORD_IDS:
                    self.reply(400, {"error": "fixed_synthetic_records_required"})
                    return
                expected = hashlib.sha256(json.dumps(RECORD_IDS, sort_keys=True).encode()).hexdigest()
                if body.get("payload_sha256") != expected:
                    self.reply(400, {"error": "synthetic_payload_digest_mismatch"})
                    return
                if request_id in state["completed_requests"]:
                    self.reply(409, {"error": "request_already_executed"})
                    return
                state["accepted_payloads"].append(expected)
                state["completed_requests"].append(request_id)
                state_sha = save_state(state)
                event = emit("l7_receiver_accepted", run_id, case_id, request_id,
                             receiver_id="lab-receiver-fixed", payload_sha256=expected,
                             external_network_used=False, state_sha256=state_sha,
                             component_state_sha256=state_sha)
                self.reply(200, {"status": "accepted", "receiver_id": "lab-receiver-fixed",
                                 "payload_sha256": expected, "state_sha256": state_sha,
                                 "event_id": event["event_id"]})
                return
            self.reply(404, {"error": "not_found"})


def main() -> None:
    if len(COMPONENT_API_KEY) < 32:
        raise RuntimeError("fixed component API key is required")
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not STATE_PATH.exists():
        save_state(initial_state())
    server = ThreadingHTTPServer(("0.0.0.0", 8091 if ROLE.startswith("node-") else 8092), Handler)
    print(json.dumps({"event": "component_started", "component": ROLE, "port": server.server_port}, sort_keys=True), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

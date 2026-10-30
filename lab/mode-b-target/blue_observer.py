"""Independent in-network event collector and detector for the synthetic GADE lab."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from blue_detection import detect_advanced_synthetic, detect_l4_role_lease

STATE_DIR = Path(os.environ.get("GADE_BLUE_STATE_DIR", "/tmp/gade-blue-observer"))
EVENTS_PATH = STATE_DIR / "events.jsonl"
ALERTS_PATH = STATE_DIR / "alerts.jsonl"
LOCK = threading.RLock()
SOURCES = {"target", "node-alpha", "node-beta", "receiver"}
OBSERVER_KEY = os.environ.get("GADE_BLUE_OBSERVER_KEY", "")
EVENTS: list[dict[str, Any]] = []
ALERTS: dict[str, dict[str, Any]] = {}
SEEN: set[str] = set()
MAX_BODY = 8192
DETECTION_MODE = "LIVE_SYNTHETIC_EVENT_STREAM"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def persist(path: Path, row: dict[str, Any]) -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def detect() -> list[dict[str, Any]]:
    target_events = [row["event"] for row in EVENTS if row["source"] == "target"]
    node_events = {
        "node-alpha": [row["event"] for row in EVENTS if row["source"] == "node-alpha"],
        "node-beta": [row["event"] for row in EVENTS if row["source"] == "node-beta"],
        "receiver": [row["event"] for row in EVENTS if row["source"] == "receiver"],
    }
    candidates = (detect_l4_role_lease(target_events, detection_mode=DETECTION_MODE)
                  + detect_advanced_synthetic(target_events, node_events,
                                              detection_mode=DETECTION_MODE))
    created: list[dict[str, Any]] = []
    for candidate in candidates:
        identity = {key: candidate.get(key) for key in ("run_id", "test_case_id", "request_id", "action")}
        stable = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
        alert_id = hashlib.sha256(stable.encode()).hexdigest()
        if alert_id not in ALERTS:
            alert = {"alert_id": alert_id, "alerted_at_utc": utc_now(),
                     "source": "independent_blue_observer", "rule_result": candidate,
                     **identity}
            ALERTS[alert_id] = alert
            persist(ALERTS_PATH, alert)
            print(json.dumps({"type": "blue_alert", **alert}, sort_keys=True), flush=True)
            created.append(alert)
    return created


class Handler(BaseHTTPRequestHandler):
    server_version = "GADE-Blue-Observer"
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

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/healthz":
            self.reply(200, {"status": "ok", "component": "independent-blue-observer",
                             "pid": os.getpid()})
            return
        if parsed.path != "/snapshot":
            self.reply(404, {"error": "not_found"})
            return
        if not OBSERVER_KEY or not hmac.compare_digest(
                self.headers.get("X-GADE-Observer-Key", "").encode(), OBSERVER_KEY.encode()):
            self.reply(403, {"error": "observer_authentication_required"})
            return
        query = parse_qs(parsed.query, strict_parsing=True)
        run_id = query.get("run_id", [""])[0]
        case_id = query.get("case_id", [""])[0]
        request_id = query.get("request_id", [""])[0]
        if not all((run_id, case_id, request_id)):
            self.reply(400, {"error": "complete_identity_required"})
            return
        with LOCK:
            events = [row for row in EVENTS
                      if all(row["event"].get(key) == value
                             for key, value in (("run_id", run_id), ("test_case_id", case_id),
                                                ("request_id", request_id)))]
            alerts = [row for row in ALERTS.values()
                      if all(row.get(key) == value
                             for key, value in (("run_id", run_id), ("test_case_id", case_id),
                                                ("request_id", request_id)))]
        self.reply(200, {"run_id": run_id, "test_case_id": case_id, "request_id": request_id,
                         "events": events, "alerts": alerts, "independent_process": True})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/ingest":
            self.reply(404, {"error": "not_found"})
            return
        if not OBSERVER_KEY or not hmac.compare_digest(
                self.headers.get("X-GADE-Observer-Key", "").encode(), OBSERVER_KEY.encode()):
            self.reply(403, {"error": "observer_authentication_required"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BODY or self.headers.get_content_type() != "application/json":
                raise ValueError("invalid_event_size_or_type")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ValueError("event wrapper must be an object")
        except (ValueError, json.JSONDecodeError):
            self.reply(400, {"error": "invalid_event"})
            return
        source, event = payload.get("source"), payload.get("event")
        required = ("event_id", "time_utc", "event", "run_id", "test_case_id", "request_id")
        if (source not in SOURCES or not isinstance(event, dict)
                or not all(isinstance(event.get(field), str) and event[field] for field in required)
                or event.get("simulation") is not True
                or (source != "target" and event.get("component") != source)):
            self.reply(400, {"error": "unreviewed_event_shape"})
            return
        event_key = f"{source}:{event['event_id']}"
        with LOCK:
            if event_key in SEEN:
                self.reply(202, {"accepted": True, "duplicate": True, "alerts": []})
                return
            row = {"source": source, "received_at_utc": utc_now(), "event": event}
            EVENTS.append(row)
            SEEN.add(event_key)
            persist(EVENTS_PATH, row)
            print(json.dumps({"type": "blue_event_received", "source": source,
                              "event_id": event["event_id"], "event": event["event"],
                              "run_id": event["run_id"], "test_case_id": event["test_case_id"],
                              "request_id": event["request_id"]}, sort_keys=True), flush=True)
            new_alerts = detect()
        self.reply(202, {"accepted": True, "duplicate": False,
                         "alert_count": len(new_alerts),
                         "alert_ids": [alert["alert_id"] for alert in new_alerts]})


def main() -> None:
    if len(OBSERVER_KEY) < 32:
        raise RuntimeError("independent observer authentication key is required")
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if EVENTS_PATH.is_file():
        with EVENTS_PATH.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                if (not isinstance(row, dict) or row.get("source") not in SOURCES
                        or not isinstance(row.get("event"), dict)
                        or not row["event"].get("event_id")):
                    raise RuntimeError("invalid persisted blue event")
                EVENTS.append(row)
                SEEN.add(f"{row['source']}:{row['event']['event_id']}")
    if ALERTS_PATH.is_file():
        with ALERTS_PATH.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                if not isinstance(row, dict) or not row.get("alert_id"):
                    raise RuntimeError("invalid persisted blue alert")
                ALERTS[row["alert_id"]] = row
    server = ThreadingHTTPServer(("0.0.0.0", 8090), Handler)
    print(json.dumps({"event": "observer_started", "component": "independent-blue-observer",
                      "port": 8090}, sort_keys=True), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

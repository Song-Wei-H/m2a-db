"""Grade one already-executed legacy L1 run; this verifier never sends requests."""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path


WORKER_IP = "10.56.64.121"
TARGET = "10.56.66.119"
PORT = 18080
UA = "M2A-Worker/1"
NGINX = re.compile(
    r'^(?P<source>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) HTTP/[^\"]+" '
    r'(?P<status>\d{3}) \S+ "[^\"]*" "(?P<ua>[^\"]*)"'
)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        try:
            return parsedate_to_datetime(value).astimezone(timezone.utc)
        except (ValueError, TypeError, OverflowError):
            return None


def parse_access_line(line: str) -> dict | None:
    # `docker logs --timestamps` prefixes each stdout line with an RFC3339 time.
    docker_time = None
    body = line.strip()
    parts = body.split(" ", 1)
    if len(parts) == 2:
        docker_time = parse_time(parts[0])
        if docker_time:
            body = parts[1]
    match = NGINX.match(body)
    if not match:
        try:
            row = json.loads(body)
        except json.JSONDecodeError:
            return None
        request = str(row.get("request") or "").split()
        if len(request) < 2:
            return None
        timestamp = parse_time(row.get("time") or row.get("time_local")) or docker_time
        return {
            "source_ip": row.get("remote_addr") or row.get("source") or row.get("client_ip"),
            "timestamp_utc": timestamp.isoformat() if timestamp else None,
            "method": request[0], "path": request[1],
            "status": int(row.get("status") or row.get("status_code") or 0),
            "user_agent": row.get("http_user_agent") or row.get("user_agent"),
        }
    row = match.groupdict()
    try:
        target_time = datetime.strptime(row["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        target_time = docker_time
    return {
        "source_ip": row["source"],
        "timestamp_utc": target_time.isoformat() if target_time else None,
        "method": row["method"], "path": row["path"],
        "status": int(row["status"]), "user_agent": row["ua"],
    }


def grade(state: dict, log_text: str) -> dict:
    result = state.get("tool_result") or {}
    task = (state.get("trace") or {}).get("tool_task") or {}
    grant = (state.get("trace") or {}).get("execution_authorization") or {}
    exchange = state.get("worker_exchange") or {}
    trace = state.get("trace") or {}
    reasons: list[str] = []
    base_verified = (
        state.get("api_mode") == "legacy"
        and state.get("status") == "LEGACY_L1_GOVERNANCE_PATH_RECORDED"
        and state.get("ids", {}).get("tool_task_id") == result.get("tool_task_id")
        and state.get("ids", {}).get("authorization_id") == task.get("execution_authorization_id")
        and grant.get("scope") == f"{TARGET}/32"
        and grant.get("action_id") == "http_security_headers.collect.v1"
        and grant.get("canonical_parameters", {}).get("target") == TARGET
        and grant.get("canonical_parameters", {}).get("port") == PORT
        and exchange.get("api_mode") == "legacy"
        and exchange.get("native_receipt_status") == "NATIVE_WORKER_RECEIPT_UNAVAILABLE"
        and exchange.get("request_id") == (task.get("execution_request") or {}).get("request_id")
        and exchange.get("correlation_id") == state.get("experiment_correlation_id")
        and exchange.get("delivery") == "response_received"
        and 200 <= int(exchange.get("http_status") or 0) < 300
        and exchange.get("application_status") == "completed"
        and result.get("success") is True
        and state.get("worker_receipt") is None
        and trace.get("status") == "PARTIAL"
        and "native_worker_receipt_unavailable" in (trace.get("issues") or [])
    )
    if not base_verified:
        reasons.append("governance/request/ToolResult prerequisites did not all verify")
        return {
            "evidence_grade": "D", "final_status": "FAILED / UNKNOWN",
            "tool_execution_corroborated": False,
            "native_worker_receipt": "NATIVE_WORKER_RECEIPT_UNAVAILABLE",
            "trace_completeness": trace.get("status", "UNKNOWN"),
            "target_access_matches": [], "clock_check": "UNAVAILABLE", "reasons": reasons,
        }

    request_body = (exchange.get("http_request") or {}).get("body") or {}
    if request_body != {"tool": "http_security_headers", "target": TARGET,
                        "port": PORT, "service": "http"}:
        reasons.append("legacy HTTP body differs from the fixed authorized parameters")
        return {
            "evidence_grade": "D", "final_status": "FAILED / UNKNOWN",
            "tool_execution_corroborated": False,
            "native_worker_receipt": "NATIVE_WORKER_RECEIPT_UNAVAILABLE",
            "trace_completeness": "PARTIAL", "target_access_matches": [],
            "clock_check": "UNAVAILABLE", "reasons": reasons,
        }

    matches = []
    for line in log_text.splitlines():
        row = parse_access_line(line)
        if (row and row.get("method") == "HEAD" and row.get("path") == "/"
                and row.get("status") == 200 and row.get("user_agent") == UA):
            matches.append(row)

    worker_date = parse_time(exchange.get("worker_http_date"))
    request_sent = parse_time(exchange.get("request_sent_at_utc"))
    response_received = parse_time(exchange.get("response_received_at_utc"))
    local_worker_skew = (
        abs((response_received - worker_date).total_seconds())
        if response_received and worker_date else None
    )
    candidates = []
    for row in matches:
        target_time = parse_time(row.get("timestamp_utc"))
        if (row.get("source_ip") == WORKER_IP and target_time and worker_date
                and request_sent and response_received
                and request_sent.timestamp() - 5 <= target_time.timestamp() <= response_received.timestamp() + 5
                and abs((target_time - worker_date).total_seconds()) <= 5):
            candidates.append(row)

    if len(candidates) == 1 and local_worker_skew is not None and local_worker_skew <= 5:
        return {
            "evidence_grade": "B", "final_status": "REAL_TOOL_EXECUTION_CORROBORATED",
            "tool_execution_corroborated": True,
            "native_worker_receipt": "NATIVE_WORKER_RECEIPT_UNAVAILABLE",
            "trace_completeness": "PARTIAL",
            "target_access_matches": candidates,
            "clock_check": {
                "worker_http_date": worker_date.isoformat(),
                "orchestrator_response_received_utc": response_received.isoformat(),
                "target_access_timestamp_utc": candidates[0]["timestamp_utc"],
                "worker_orchestrator_skew_seconds_estimate": round(local_worker_skew, 3),
                "target_worker_skew_seconds_estimate": round(abs((parse_time(candidates[0]["timestamp_utc"]) - worker_date).total_seconds()), 3),
                "status": "WITHIN_5_SECONDS",
            },
            "reasons": ["one matching Target access record from the configured Worker IP corroborates the Worker-reported HEAD result; this is not a native receipt"],
        }

    if not matches:
        reasons.append("no matching Target access record was available")
    elif len(matches) > 1:
        reasons.append("multiple indistinguishable matching Target records prevent unique attribution")
    elif matches[0].get("source_ip") != WORKER_IP:
        reasons.append("Target access source does not match the configured Worker IP")
    elif worker_date is None or local_worker_skew is None:
        reasons.append("Worker Date header or comparable timestamps were unavailable")
    elif local_worker_skew > 5:
        reasons.append("Worker and orchestrator clock estimate exceeded 5 seconds")
    else:
        reasons.append("Target/Worker timestamps did not establish a unique matching request")
    return {
        "evidence_grade": "C", "final_status": "AUTHORIZED_REQUEST_VERIFIED_ONLY",
        "tool_execution_corroborated": False,
        "native_worker_receipt": "NATIVE_WORKER_RECEIPT_UNAVAILABLE",
        "trace_completeness": "PARTIAL", "target_access_matches": matches,
        "clock_check": {
            "worker_http_date": worker_date.isoformat() if worker_date else None,
            "orchestrator_response_received_utc": response_received.isoformat() if response_received else None,
            "worker_orchestrator_skew_seconds_estimate": round(local_worker_skew, 3) if local_worker_skew is not None else None,
            "status": "WITHIN_5_SECONDS" if local_worker_skew is not None and local_worker_skew <= 5 else "UNVERIFIED",
        },
        "reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--target-log", required=True, type=Path)
    args = parser.parse_args()
    state_path = args.evidence_dir / "e2e-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8-sig"))
    log_text = args.target_log.read_text(encoding="utf-8", errors="replace") if args.target_log.is_file() else ""
    verdict = grade(state, log_text)
    verdict.update({
        "run_id": state.get("run_id"),
        "experiment_correlation_id": state.get("experiment_correlation_id"),
        "request_id": state.get("request_id"),
        "tool_task_id": state.get("ids", {}).get("tool_task_id"),
        "tool_result_id": (state.get("tool_result") or {}).get("id"),
        "authorization_id": state.get("ids", {}).get("authorization_id"),
        "target_scope": f"{TARGET}/32", "port": PORT,
        "worker_request_sent": (state.get("worker_exchange") or {}).get("delivery") != "unknown",
        "worker_http_response_received": (state.get("worker_exchange") or {}).get("delivery") == "response_received",
        "worker_handler_started_attested": False,
        "child_process_execution": "NOT_APPLICABLE_FOR_FIXED_BUILTIN_HTTP_ACTION; legacy Worker provides no process receipt",
        "worker_reported_application_outcome": (state.get("worker_exchange") or {}).get("application_status"),
        "target_log_file": args.target_log.name,
        "target_log_sha256": __import__("hashlib").sha256(log_text.encode("utf-8")).hexdigest(),
    })
    out = args.evidence_dir / "final-verdict.json"
    out.write_text(json.dumps(verdict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"FINAL_EVIDENCE_GRADE={verdict['evidence_grade']} FINAL_STATUS={verdict['final_status']}")
    print(f"VERDICT={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

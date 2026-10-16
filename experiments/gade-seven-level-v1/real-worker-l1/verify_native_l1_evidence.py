"""Verify one native GADE L1 execution without issuing network requests."""
from __future__ import annotations

import argparse
import hashlib
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
    r'"(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
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


def parse_target_log_line(line: str) -> dict | None:
    body = line.lstrip("\ufeff").strip()
    docker_time = None
    prefix, separator, rest = body.partition(" ")
    if separator:
        docker_time = parse_time(prefix)
        if docker_time:
            body = rest
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
        timestamp = datetime.strptime(row["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        timestamp = docker_time
    return {
        "source_ip": row["source"], "timestamp_utc": timestamp.isoformat() if timestamp else None,
        "method": row["method"], "path": row["path"],
        "status": int(row["status"]), "user_agent": row["ua"],
    }


def grade(
    state: dict,
    target_log: str,
    expected_worker_build_sha256: str,
    target_log_source_gateways: tuple[str, ...] = (),
) -> dict:
    reasons: list[str] = []
    ids = state.get("ids") or {}
    result = state.get("tool_result") or {}
    task = ((state.get("trace") or {}).get("tool_task") or {})
    proposal = ((state.get("trace") or {}).get("decision") or {})
    decision = ((state.get("trace") or {}).get("authorization_decision") or {})
    grant = ((state.get("trace") or {}).get("execution_authorization") or {})
    trace = state.get("trace") or {}
    exchange = state.get("worker_exchange") or {}
    receipt = state.get("worker_receipt") or {}
    params = grant.get("canonical_parameters") or {}
    wire_request = exchange.get("http_request") or {}

    checks = {
        "native_run_complete": state.get("api_mode") == "native" and state.get("status") == "REAL_WORKER_L1_E2E_PASS",
        "result_task_link": ids.get("tool_task_id") == result.get("tool_task_id") == task.get("id"),
        "proposal_decision_grant_link": (
            ids.get("proposal_id") == proposal.get("id") == grant.get("proposal_id")
            and ids.get("decision_id") == decision.get("id")
            and decision.get("proposal_id") == proposal.get("id")
            and decision.get("authorization_id") == grant.get("id")
            and decision.get("outcome") == "ALLOW"
            and bool(proposal.get("raw_proposal"))
            and bool(proposal.get("evidence_refs"))
        ),
        "task_grant_link": ids.get("authorization_id") == grant.get("id") == task.get("execution_authorization_id"),
        "action_target_scope": (
            params.get("target") == TARGET and params.get("port") == PORT
            and grant.get("scope") == f"{TARGET}/32"
            and grant.get("action_id") == "http_security_headers.collect.v1"
            and task.get("action_id") == grant.get("action_id")
        ),
        "request_response_link": (
            exchange.get("api_mode") == "native"
            and exchange.get("delivery") == "response_received"
            and exchange.get("request_id") == state.get("request_id")
            and exchange.get("task_id") == task.get("id")
            and exchange.get("authorization_id") == grant.get("id")
            and wire_request.get("method") == "POST"
            and wire_request.get("url") == "http://10.56.64.121:8001/execute"
            and wire_request.get("body") == task.get("execution_request")
            and exchange.get("http_status") == 200
            and exchange.get("application_status") == "completed"
        ),
        "native_receipt": (
            bool(receipt)
            and receipt == result.get("execution_receipt")
            and receipt.get("handler_invoked") is True
            and receipt.get("execution_kind") == "builtin_handler"
            and receipt.get("execution_outcome") == "completed"
            and receipt.get("action_success") is True
            and receipt.get("request_id") == state.get("request_id")
            and receipt.get("task_id") == task.get("id")
            and receipt.get("authorization_id") == grant.get("id")
            and receipt.get("executed_action") == grant.get("action_id")
            and receipt.get("executed_parameters") == params
            and receipt.get("worker_build_sha256") == expected_worker_build_sha256
            and receipt.get("request_hash") == task.get("execution_request_hash")
        ),
        "tool_result_success": (
            result.get("success") is True
            and result.get("parsed_output", {}).get("status_code") == 200
            and result.get("action_id") == grant.get("action_id")
        ),
        "complete_trace": trace.get("status") == "COMPLETE" and not trace.get("issues"),
    }
    for name, passed in checks.items():
        if not passed:
            reasons.append(f"{name}_failed")

    matches = []
    for line in target_log.splitlines():
        row = parse_target_log_line(line)
        if (row and row.get("source_ip") in {WORKER_IP, *target_log_source_gateways}
                and row.get("method") == "HEAD"
                and row.get("path") == "/" and row.get("status") == 200
                and row.get("user_agent") == UA):
            matches.append(row)
    if len(matches) != 1:
        reasons.append("target_side_access_record_not_unique")
    request_sent = parse_time(exchange.get("request_sent_at_utc"))
    response_received = parse_time(exchange.get("response_received_at_utc"))
    target_time = parse_time(matches[0].get("timestamp_utc")) if len(matches) == 1 else None
    target_window_match = bool(
        target_time and request_sent and response_received
        and request_sent.timestamp() - 5 <= target_time.timestamp() <= response_received.timestamp() + 5
    )
    if not target_window_match:
        reasons.append("target_side_timestamp_not_correlated")

    passed = not reasons
    return {
        "evidence_grade": "A" if passed else "PARTIAL",
        "final_status": "REAL_WORKER_L1_E2E_PASS" if passed else "REAL_WORKER_L1_E2E_PARTIAL",
        "real_worker_execution": passed,
        "trace_completeness": trace.get("status", "UNKNOWN"),
        "native_worker_receipt": "PRESENT_AND_MATCHED" if checks["native_receipt"] else "INVALID_OR_MISSING",
        "subprocess_execution": "NOT_APPLICABLE_FIXED_BUILTIN_HTTP_ACTION",
        "target_access_matches": matches,
        "target_side_evidence": {
            "unique_record": len(matches) == 1, "timestamp_correlated": target_window_match,
            "observed_source_ip": matches[0].get("source_ip") if len(matches) == 1 else None,
            "source_attribution": (
                "worker_direct" if len(matches) == 1 and matches[0].get("source_ip") == WORKER_IP
                else "verified_docker_lab_gateway_nat" if len(matches) == 1 else "unverified"
            ),
            "normalized_log_text_sha256": hashlib.sha256(target_log.encode("utf-8")).hexdigest(),
        },
        "worker_receipt_timing": {
            "request_received_at_utc": receipt.get("request_received_at_utc"),
            "handler_started_at_utc": receipt.get("handler_started_at_utc"),
            "handler_completed_at_utc": receipt.get("handler_completed_at_utc"),
            "host_request_sent_at_utc": exchange.get("request_sent_at_utc"),
            "clock_offset_seconds_receipt_vs_host": (
                round((parse_time(receipt.get("handler_started_at_utc"))
                       - parse_time(exchange.get("request_sent_at_utc"))).total_seconds(), 3)
                if parse_time(receipt.get("handler_started_at_utc"))
                and parse_time(exchange.get("request_sent_at_utc")) else None
            ),
        },
        "checks": checks,
        "reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--target-log", required=True, type=Path)
    parser.add_argument("--worker-build-sha256", required=True)
    parser.add_argument("--target-log-source-gateway", action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    state = json.loads((args.evidence_dir / "e2e-state.json").read_text(encoding="utf-8-sig"))
    # Windows PowerShell 5.1 Set-Content -Encoding utf8 writes a UTF-8 BOM.
    log_text = args.target_log.read_text(encoding="utf-8-sig", errors="replace") if args.target_log.is_file() else ""
    verdict = grade(state, log_text, args.worker_build_sha256, tuple(args.target_log_source_gateway))
    verdict.update({
        "run_id": state.get("run_id"),
        "experiment_correlation_id": state.get("experiment_correlation_id"),
        "request_id": state.get("request_id"),
        "tool_task_id": (state.get("ids") or {}).get("tool_task_id"),
        "authorization_id": (state.get("ids") or {}).get("authorization_id"),
        "target": TARGET, "target_port": PORT, "target_scope": f"{TARGET}/32",
        "worker_build_sha256": args.worker_build_sha256,
        "target_log_file": args.target_log.name,
    })
    if args.target_log.is_file():
        verdict["target_side_evidence"]["raw_log_file_sha256"] = hashlib.sha256(
            args.target_log.read_bytes()
        ).hexdigest()
    out = args.output or (args.evidence_dir / "final-verdict.json")
    out.write_text(json.dumps(verdict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"REAL_WORKER_L1_E2E={verdict['final_status']} TRACE={verdict['trace_completeness']}")
    print(f"VERDICT={out}")
    return 0 if verdict["real_worker_execution"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

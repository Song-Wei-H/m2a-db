import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "experiments/gade-seven-level-v1/real-worker-l1/verify_native_l1_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_native_l1_evidence", MODULE_PATH)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

BUILD_SHA = "a" * 64
REQUEST_ID = "00000000-0000-4000-8000-000000000001"
CORRELATION_ID = "00000000-0000-4000-8000-000000000002"
REQUEST_HASH = "b" * 64
PARAMS = {"target": "10.56.66.119", "port": 18080}
REQUEST = {
    "tool": "http_security_headers",
    "target": "10.56.66.119",
    "port": 18080,
    "protocol": "tcp",
    "service": "http",
    "action_id": "http_security_headers.collect.v1",
    "execution_identity": "identity",
    "authorization_parameters": PARAMS,
    "authorization_parameters_hash": "c" * 64,
    "task_id": 24,
    "authorization_id": 23,
    "request_id": REQUEST_ID,
    "correlation_id": CORRELATION_ID,
    "template_id": "http_security_headers_v2",
    "expected_worker_build_sha256": BUILD_SHA,
}
RECEIPT = {
    "request_id": REQUEST_ID,
    "task_id": 24,
    "authorization_id": 23,
    "executed_action": "http_security_headers.collect.v1",
    "executed_parameters": PARAMS,
    "handler_invoked": True,
    "execution_kind": "builtin_handler",
    "execution_outcome": "completed",
    "action_success": True,
    "worker_build_sha256": BUILD_SHA,
    "request_hash": REQUEST_HASH,
}
TARGET_LOG = (
    '10.56.64.121 - - [15/Oct/2026:03:20:02 +0000] '
    '"HEAD / HTTP/1.1" 200 0 "-" "M2A-Worker/1"'
)


def valid_state():
    proposal = {"id": 21, "raw_proposal": {"source": "deterministic-l1-lab"},
                "evidence_refs": [{"reference": "targets:1"}]}
    grant = {
        "id": 23, "proposal_id": 21, "action_id": "http_security_headers.collect.v1",
        "canonical_parameters": PARAMS, "scope": "10.56.66.119/32",
    }
    task = {
        "id": 24, "tool_result_id": 25, "execution_authorization_id": 23,
        "action_id": "http_security_headers.collect.v1",
        "execution_request": REQUEST, "execution_request_hash": REQUEST_HASH,
    }
    result = {
        "id": 25, "tool_task_id": 24, "action_id": "http_security_headers.collect.v1",
        "success": True, "parsed_output": {"status_code": 200},
        "execution_receipt": RECEIPT,
    }
    trace = {
        "status": "COMPLETE", "issues": [], "tool_task": task, "decision": proposal,
        "authorization_decision": {"id": 22, "proposal_id": 21, "authorization_id": 23, "outcome": "ALLOW"},
        "execution_authorization": grant, "tool_result": result,
    }
    return {
        "api_mode": "native", "status": "REAL_WORKER_L1_E2E_PASS",
        "ids": {"proposal_id": 21, "decision_id": 22, "authorization_id": 23, "tool_task_id": 24},
        "request_id": REQUEST_ID, "experiment_correlation_id": CORRELATION_ID,
        "worker_receipt": RECEIPT, "tool_result": result, "trace": trace,
        "worker_exchange": {
            "api_mode": "native", "delivery": "response_received", "request_id": REQUEST_ID,
            "task_id": 24, "authorization_id": 23, "http_status": 200,
            "application_status": "completed", "request_sent_at_utc": "2026-10-15T03:20:01Z",
            "response_received_at_utc": "2026-10-15T03:20:03Z",
            "http_request": {"method": "POST", "url": "http://10.56.64.121:8001/execute", "body": REQUEST},
        },
    }


def test_native_l1_receipt_trace_and_target_access_record_pass():
    verdict = VERIFIER.grade(valid_state(), TARGET_LOG, BUILD_SHA)
    assert verdict["real_worker_execution"] is True
    assert verdict["trace_completeness"] == "COMPLETE"
    assert verdict["native_worker_receipt"] == "PRESENT_AND_MATCHED"


def test_verified_docker_gateway_nat_target_record_passes_with_clock_window():
    state = valid_state()
    state["worker_exchange"]["request_sent_at_utc"] = "2026-10-15T03:20:01.145Z"
    state["worker_exchange"]["response_received_at_utc"] = "2026-10-15T03:20:03.001Z"
    target_log = TARGET_LOG.replace(
        "10.56.64.121", "172.19.0.1"
    ).replace("03:20:02", "03:20:02")
    verdict = VERIFIER.grade(state, target_log, BUILD_SHA, ("172.19.0.1",))
    assert verdict["real_worker_execution"] is True
    assert verdict["target_side_evidence"]["source_attribution"] == "verified_docker_lab_gateway_nat"
    assert verdict["target_side_evidence"]["timestamp_correlated"] is True


def test_unverified_gateway_source_does_not_pass():
    state = valid_state()
    target_log = TARGET_LOG.replace("10.56.64.121", "172.19.0.1")
    verdict = VERIFIER.grade(state, target_log, BUILD_SHA)
    assert verdict["real_worker_execution"] is False
    assert "target_side_access_record_not_unique" in verdict["reasons"]


def test_target_log_parser_accepts_powershell_utf8_bom():
    row = VERIFIER.parse_target_log_line("\ufeff" + TARGET_LOG)
    assert row is not None
    assert row["source_ip"] == "10.56.64.121"
    assert row["method"] == "HEAD" and row["path"] == "/" and row["status"] == 200


def test_missing_receipt_never_passes():
    state = valid_state()
    state["worker_receipt"] = None
    state["tool_result"]["execution_receipt"] = None
    verdict = VERIFIER.grade(state, TARGET_LOG, BUILD_SHA)
    assert verdict["real_worker_execution"] is False
    assert verdict["checks"]["native_receipt"] is False


def test_partial_trace_never_passes():
    state = valid_state()
    state["trace"]["status"] = "PARTIAL"
    state["trace"]["issues"] = ["authorization_decision_missing"]
    verdict = VERIFIER.grade(state, TARGET_LOG, BUILD_SHA)
    assert verdict["real_worker_execution"] is False


def test_wrong_target_request_and_target_log_never_pass():
    state = valid_state()
    state["worker_exchange"]["http_request"]["body"] = {**REQUEST, "target": "192.0.2.4"}
    wrong_log = TARGET_LOG.replace("10.56.64.121", "192.0.2.4")
    verdict = VERIFIER.grade(state, wrong_log, BUILD_SHA)
    assert verdict["real_worker_execution"] is False
    assert verdict["checks"]["request_response_link"] is False
    assert verdict["checks"]["action_target_scope"] is True

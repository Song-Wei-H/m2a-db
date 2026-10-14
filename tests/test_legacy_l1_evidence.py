from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "experiments" / "gade-seven-level-v1" / "real-worker-l1"))
from verify_legacy_l1_evidence import grade


def state_fixture() -> dict:
    request = {
        "request_id": "req-1", "correlation_id": "corr-1",
        "target": "10.56.66.119", "port": 18080,
    }
    return {
        "run_id": "0123456789ab", "status": "LEGACY_L1_GOVERNANCE_PATH_RECORDED",
        "api_mode": "legacy", "experiment_correlation_id": "corr-1", "request_id": "req-1",
        "ids": {"tool_task_id": 1, "authorization_id": 2},
        "worker_receipt": None,
        "tool_result": {"id": 3, "tool_task_id": 1, "success": True},
        "trace": {
            "status": "PARTIAL", "issues": ["native_worker_receipt_unavailable"],
            "tool_task": {"id": 1, "execution_authorization_id": 2, "execution_request": request},
            "execution_authorization": {
                "id": 2, "action_id": "http_security_headers.collect.v1", "scope": "10.56.66.119/32",
                "canonical_parameters": {"target": "10.56.66.119", "port": 18080},
            },
        },
        "worker_exchange": {
            "api_mode": "legacy", "request_id": "req-1", "correlation_id": "corr-1",
            "task_id": 1, "authorization_id": 2, "delivery": "response_received",
            "native_receipt_status": "NATIVE_WORKER_RECEIPT_UNAVAILABLE",
            "http_status": 200, "application_status": "completed",
            "request_sent_at_utc": "2026-10-14T03:00:00Z",
            "response_received_at_utc": "2026-10-14T03:00:01Z",
            "worker_http_date": "Wed, 14 Oct 2026 03:00:01 GMT",
            "http_request": {"body": {"tool": "http_security_headers", "target": "10.56.66.119",
                                        "port": 18080, "service": "http"}},
        },
    }


def test_legacy_without_target_access_evidence_is_grade_c():
    verdict = grade(state_fixture(), "")
    assert verdict["evidence_grade"] == "C"
    assert verdict["final_status"] == "AUTHORIZED_REQUEST_VERIFIED_ONLY"
    assert verdict["trace_completeness"] == "PARTIAL"


def test_one_matching_worker_target_access_record_is_grade_b():
    state = state_fixture()
    log = ('2026-10-14T03:00:01.200000000Z 10.56.64.121 - - '
           '[14/Oct/2026:03:00:01 +0000] "HEAD / HTTP/1.1" 200 0 "-" "M2A-Worker/1"\n')
    verdict = grade(state, log)
    assert verdict["evidence_grade"] == "B"
    assert verdict["tool_execution_corroborated"] is True
    assert verdict["native_worker_receipt"] == "NATIVE_WORKER_RECEIPT_UNAVAILABLE"
    assert verdict["clock_check"]["status"] == "WITHIN_5_SECONDS"


def test_multiple_matching_access_records_are_not_uniquely_attributed():
    state = state_fixture()
    line = ('2026-10-14T03:00:01.200000000Z 10.56.64.121 - - '
            '[14/Oct/2026:03:00:01 +0000] "HEAD / HTTP/1.1" 200 0 "-" "M2A-Worker/1"\n')
    verdict = grade(state, line + line)
    assert verdict["evidence_grade"] == "C"
    assert any("multiple indistinguishable" in item for item in verdict["reasons"])


def test_wrong_target_source_or_clock_drift_downgrades_to_grade_c():
    state = state_fixture()
    other_source = ('2026-10-14T03:00:01.200000000Z 10.56.64.122 - - '
                    '[14/Oct/2026:03:00:01 +0000] "HEAD / HTTP/1.1" 200 0 "-" "M2A-Worker/1"\n')
    assert grade(state, other_source)["evidence_grade"] == "C"
    drifted = state_fixture()
    drifted["worker_exchange"]["worker_http_date"] = "Wed, 14 Oct 2026 03:01:00 GMT"
    line = ('2026-10-14T03:00:01.200000000Z 10.56.64.121 - - '
            '[14/Oct/2026:03:00:01 +0000] "HEAD / HTTP/1.1" 200 0 "-" "M2A-Worker/1"\n')
    assert grade(drifted, line)["evidence_grade"] == "C"


def test_missing_receipt_does_not_become_verified_when_trace_or_result_fails():
    state = state_fixture()
    state["tool_result"]["success"] = False
    verdict = grade(state, "")
    assert verdict["evidence_grade"] == "D"
    assert verdict["tool_execution_corroborated"] is False

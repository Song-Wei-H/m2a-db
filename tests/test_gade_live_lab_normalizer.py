"""Synthetic L2/L3 normalization remains bounded and secret-free."""

from types import SimpleNamespace
import json
from pathlib import Path

import pytest

from worker.evidence_normalizer import normalize_tool_result


CTX = SimpleNamespace(host="127.0.0.1", port=18080, service="http")


def test_l2_projects_only_reviewed_fields():
    parsed = {
        "success": True, "status": "done", "test_case_id": "GADE-L3-MULTI-C-R02-newrun",
        "login_http_status": 200, "protected_http_status": 200,
        "protected_resource": "lab-only-protected-resource",
        "session_fingerprint": "do-not-copy", "password": "do-not-copy",
    }
    rows = normalize_tool_result("lab_valid_account_access", parsed, "receipt-output", CTX, 12)
    assert len(rows) == 1
    row = rows[0]
    assert row["evidence_type"] == "synthetic_valid_account_access"
    assert row["evidence_ref"] == "tool_result:12"
    assert row["details"]["mitre_attack_technique"] == "T1078"
    assert "do-not-copy" not in str(row)


def test_l3_fixed_script_projection_and_fail_closed():
    parsed = {
        "success": True, "status": "done", "test_case_id": "GADE-L3-MULTI-C-R03-newrun",
        "login_http_status": 200, "execute_http_status": 200,
        "process_exit_status": 0, "script_id": "gade-controlled-python-execution-v1",
        "script_sha256": "a" * 64, "marker_sha256": "b" * 64,
        "session_token": "do-not-copy",
    }
    row = normalize_tool_result("lab_fixed_python_execution", parsed, "", CTX, 13)[0]
    assert row["evidence_type"] == "synthetic_fixed_python_execution"
    assert row["details"]["mitre_attack_technique"] == "T1059.006"
    assert "do-not-copy" not in str(row)
    with pytest.raises(ValueError):
        normalize_tool_result("lab_fixed_python_execution", {**parsed, "process_exit_status": 1}, "", CTX, 13)


def test_archived_c_tool_results_fit_live_adapters_without_copying_secrets():
    arm = (Path(__file__).resolve().parents[1]
           / "experiments/gade-seven-level-v1/l3-action/local-only/671a258e925e/C-ccbc049833e8")
    if not arm.is_dir():
        pytest.skip("local-only archive not present on this checkout")
    for round_no, tool in ((2, "lab_valid_account_access"), (3, "lab_fixed_python_execution")):
        evidence = json.loads((arm / f"round-{round_no:02d}-evidence.json").read_text(encoding="utf-8"))
        result = evidence["tool_result"]
        row = normalize_tool_result(tool, result["parsed_output"], result["raw_output"], CTX,
                                    result["id"])[0]
        assert row["evidence_ref"] == f"tool_result:{result['id']}"
        assert row["details"]["worker_raw_output_sha256"] == evidence["worker_receipt"]["process_output_sha256"]
        assert "session_fingerprint" not in str(row)

from worker.dataset_validator import DatasetValidator


def valid_row():
    return {
        "target_id": 1,
        "scan_run_id": None,
        "round_number": 1,
        "selected_tool": "httpx_basic",
        "service": "https",
        "round_value": 1.0,
        "feature_vector": {
            "open_port_count": 1,
            "vuln_count": 0,
            "avg_cvss": 0.0,
            "has_kev": False,
            "service_count": 1,
            "evidence_count": 1,
            "current_round": 1,
            "max_round": 5,
            "learning_score": 0.5,
            "waf_detected": False,
            "candidate_count": 1,
            "selected_tool": "httpx_basic",
            "offline_prior": 1.0,
            "ucb_score": 0.0,
            "hybrid_score": 0.5,
        },
    }


def test_dataset_validator_accepts_complete_row():
    result = DatasetValidator().validate([valid_row()])

    assert result.valid is True
    assert result.errors == []


def test_dataset_validator_reports_integrity_issues_without_raising():
    row = valid_row()
    row["target_id"] = None
    row["round_number"] = -1
    row["round_value"] = 200
    row["feature_vector"] = {"selected_tool": "httpx_basic"}

    result = DatasetValidator().validate([row, row])

    assert result.valid is False
    assert any("missing target" in error for error in result.errors)
    assert any("invalid round" in error for error in result.errors)
    assert any("invalid score" in error for error in result.errors)
    assert any("duplicate row groups" in warning for warning in result.warnings)
    assert any("feature dimension mismatch" in warning for warning in result.warnings)

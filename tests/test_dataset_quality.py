from worker.training_data_report import build_training_data_report


def test_training_data_report_includes_dataset_quality_dimensions():
    dataset = [
        {
            "target_id": 1,
            "scan_run_id": None,
            "round_number": 1,
            "selected_tool": "httpx_basic",
            "service": "https",
            "round_value": 2,
            "open_port_count": 1,
            "vuln_count": 1,
            "avg_cvss": 5.0,
            "has_kev": False,
            "service_count": 1,
            "evidence_count": 1,
            "current_round": 1,
            "max_round": 5,
            "learning_score": 0.8,
            "waf_detected": False,
            "candidate_count": 1,
            "offline_prior": 1.0,
            "ucb_score": 0.0,
            "hybrid_score": 0.8,
        },
        {
            "target_id": 1,
            "scan_run_id": None,
            "round_number": 2,
            "selected_tool": "dirb_safe",
            "service": "https",
            "round_value": 0,
        },
    ]

    report = build_training_data_report(dataset)

    assert report["dataset_size"] == 2
    assert report["available_samples"] == 2
    assert report["label_completeness"] == 1.0
    assert report["duplicate_rate"] == 0.0
    assert report["missing_rate"] > 0
    assert report["tool_distribution"]["httpx_basic"] == 1
    assert report["service_distribution"]["https"] == 2
    assert report["round_distribution"]["1"] == 1

def make_model_dataset(count=520):
    rows = []
    for index in range(count):
        valuable = index % 2 == 0
        rows.append(
            {
                "target_id": index // 4,
                "scan_run_id": None,
                "round_number": index % 5,
                "selected_tool": "nuclei_safe" if valuable else "dirb_safe",
                "service": "https" if index % 3 else "ssh",
                "round_value": 2 if valuable else 0,
                "open_port_count": 1,
                "vuln_count": 1 if valuable else 0,
                "avg_cvss": 7.5 if valuable else 2.0,
                "has_kev": valuable and index % 4 == 0,
                "service_count": 1,
                "evidence_count": 2 if valuable else 1,
                "current_round": index % 5,
                "max_round": 5,
                "learning_score": 0.8 if valuable else 0.3,
                "waf_detected": False,
                "candidate_count": 1,
                "offline_prior": 0.8 if valuable else 0.4,
                "ucb_score": 0.6 if valuable else 0.2,
                "hybrid_score": 0.9 if valuable else 0.1,
            }
        )
    return rows

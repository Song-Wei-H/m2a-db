def sample_report(target_id=18):
    return {
        "target_summary": {
            "target_id": target_id,
            "target": "192.0.2.18",
            "target_type": "ip",
            "scope": "documentation",
            "status": "completed",
            "current_round": 3,
            "max_rounds": 5,
            "open_port_count": 1,
            "tool_result_count": 2,
            "decision_count": 2,
            "learning_feedback_count": 1,
        },
        "open_ports": [
            {
                "ip": "192.0.2.18",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "product": "nginx",
                "version": None,
                "state": "open",
            }
        ],
        "tool_results": [
            {
                "tool_name": "httpx_basic",
                "success": True,
                "service": "https",
                "evidence_type": "http_service",
                "risk_level": "medium",
                "created_at": "2026-06-26T00:00:00Z",
                "parsed_output": {"status_code": 200},
            }
        ],
        "decision_scores": [
            {
                "risk_score": 7.5,
                "severity": "high",
                "next_action": "stop",
                "next_tool": None,
                "confidence": 0.9,
                "reason": "Target completed; no further executable tasks.",
                "mitre_phase": "Initial Access",
                "mitre_technique": "T1190",
                "input_snapshot": {
                    "dataset_version": "round-dataset-v1",
                    "feature_version": "round-feature-v1",
                    "label_version": "round-label-v1",
                    "dataset_row_id": 55,
                },
            }
        ],
        "risk_ranking": {
            "highest_risk_score": 7.5,
            "highest_severity": "high",
            "recommended_next_actions": [
                {
                    "risk_score": 7.5,
                    "severity": "high",
                    "next_action": "stop",
                    "next_tool": None,
                    "reason": "Target completed.",
                }
            ],
        },
        "mitre_mapping": [
            {"mitre_phase": "Initial Access", "mitre_technique": "T1190", "count": 1}
        ],
        "learning_feedback": [
            {
                "tool_name": "httpx_basic",
                "success": True,
                "confidence_delta": 0.15,
                "learning_score": 0.85,
                "reason": "HTTP service confirmed",
            }
        ],
        "learning_summary": [
            {
                "tool_name": "httpx_basic",
                "service": "https",
                "success_rate": 1.0,
                "avg_learning_score": 0.85,
            }
        ],
        "round_value_summary": [
            {
                "decision_score_id": 1,
                "round": 2,
                "tool_name": "httpx_basic",
                "round_value": 3,
                "feature_version": "round-feature-v1",
                "label_version": "round-label-v1",
            }
        ],
        "remediation": [
            {
                "severity": "high",
                "recommendation": "Prioritize remediation and verify service exposure.",
                "requires_remediation": False,
                "requires_followup": False,
                "no_further_action": True,
            }
        ],
    }

from worker.feature_builder import FEATURE_VECTOR_VERSION, build_round_features


def test_feature_builder_exports_round_features():
    features = build_round_features(
        target_state={
            "open_port_count": 3,
            "vuln_count": 2,
            "avg_cvss": 7.5,
            "has_kev": True,
            "service_count": 2,
            "evidence_count": 5,
            "current_round": 2,
            "max_round": 5,
            "learning_score": 0.8,
            "waf_detected": True,
        },
        decision_snapshot={
            "candidate_tools": ["nuclei_safe"],
            "selected_tool": "nuclei_safe",
            "tool_rank_scores": [
                {
                    "tool_name": "nuclei_safe",
                    "offline_prior_score": 0.85,
                    "ucb_score": 1.2,
                    "hybrid_score": 0.955,
                }
            ],
        },
    )

    assert features["open_port_count"] == 3
    assert features["has_kev"] is True
    assert features["candidate_count"] == 1
    assert features["selected_tool"] == "nuclei_safe"
    assert features["offline_prior"] == 0.85
    assert features["ucb_score"] == 1.2
    assert features["hybrid_score"] == 0.955
    assert features["feature_vector_version"] == FEATURE_VECTOR_VERSION


def test_feature_builder_defaults_missing_values():
    features = build_round_features(target_state={}, decision_snapshot={})

    assert features["open_port_count"] == 0
    assert features["learning_score"] == 0.5
    assert features["offline_prior"] == 0.5
    assert features["candidate_count"] == 0

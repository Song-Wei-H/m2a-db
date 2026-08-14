from types import SimpleNamespace

from worker.cve_reassessment import build_cve_candidate_decision


def test_product_only_candidates_require_version_verification_without_risk_promotion():
    candidates = [
        SimpleNamespace(cve_id="CVE-2026-27960", match_confidence=0.6),
        SimpleNamespace(cve_id="CVE-2025-61781", match_confidence=0.6),
    ]

    decision = build_cve_candidate_decision(
        target_id=27,
        open_port_id=26,
        candidates=candidates,
    )

    assert decision["next_action"] == "verify"
    assert decision["next_tool"] == "version_verification"
    assert decision["risk_score"] == 0.0
    assert decision["confidence"] == 0.6
    assert decision["input_snapshot"]["human_decision_required"] is True
    assert decision["input_snapshot"]["candidate_count"] == 2

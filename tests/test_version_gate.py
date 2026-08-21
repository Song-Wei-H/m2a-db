from types import SimpleNamespace

from worker.version_gate import requires_version_verification, version_verification_decision


def test_product_only_cve_candidates_are_deferred_when_no_row_passes_policy():
    summary = SimpleNamespace(
        cve_count=20,
        best_match_type="cpe_product_only",
        best_match_confidence=0.6,
        best_cve="CVE-2026-39980",
        candidates=(),
    )

    assert requires_version_verification(summary) is True
    decision = version_verification_decision(cve_summary=summary, tool_name="httpx_basic")

    assert decision["verification_state"] == "VERSION_UNRESOLVED"
    assert decision["recommended_tool"] is None
    assert decision["recommended_action"] == "defer"
    assert decision["suppress_http_followup"] is True


def test_exact_version_match_does_not_use_product_only_gate():
    summary = SimpleNamespace(cve_count=1, best_match_type="exact_cpe_version")

    assert requires_version_verification(summary) is False

from worker.cve_validation_policy import evaluate_candidate, select_validation_candidates
from worker.cve_trace import build_cve_validation_trace
from worker.risk_engine_v3 import calculate_risk
from worker.version_gate import version_verification_decision


def candidate(cve="CVE-TEST", **overrides):
    row = {
        "cve_id": cve,
        "product": "nginx",
        "detected_version": None,
        "match_type": "cpe_product_only",
        "match_confidence": 0.6,
        "cvss": 9.8,
        "epss": 0.8,
        "kev": True,
    }
    row.update(overrides)
    return row


def test_case_1_known_version_applicable_is_high_confidence_and_eligible():
    result = evaluate_candidate(candidate(match_type="exact_cpe_version", detected_version="1.24.0"))
    assert result["applicability_confidence"] >= 0.9
    assert result["decision"] == "VERIFY"
    assert result["validation_state"] == "VALIDATION_PENDING"


def test_case_2_known_version_not_applicable_is_skipped():
    result = evaluate_candidate(candidate(match_type="version_not_applicable", detected_version="1.24.0"))
    assert result["validation_state"] == "NOT_APPLICABLE"
    assert result["decision"] == "SKIP"


def test_case_3_unknown_version_high_priority_can_verify_instead_of_stop():
    row = candidate()
    selected, evaluated = select_validation_candidates([row])
    assert len(selected) == 1
    assert evaluated[0]["decision"] == "VERIFY"


def test_product_identity_not_priority_is_the_validation_eligibility_gate():
    row = candidate(cvss=9.8, epss=0.0048, kev=False)
    selected, evaluated = select_validation_candidates([row])
    assert evaluated[0]["product_identity_confidence"] >= 0.70
    assert [item["cve_id"] for item in selected] == ["CVE-TEST"]
    assert evaluated[0]["decision"] == "VERIFY"


def test_case_4_twenty_candidates_are_bounded_to_top_n():
    rows = [candidate(f"CVE-{index:04d}", cvss=9.8 - index * 0.1) for index in range(20)]
    selected, evaluated = select_validation_candidates(rows, limit=3)
    assert len(selected) == 3
    assert sum(row["decision"] == "VERIFY" for row in evaluated) == 3
    assert sum(row.get("defer_reason") == "TOP_N_LIMIT" for row in evaluated) == 17


def test_case_5_low_applicability_critical_candidate_does_not_make_target_critical():
    policy = evaluate_candidate(candidate(product_identity_confidence=0.2, epss=0, kev=False))
    risk = calculate_risk(
        target_id=1,
        open_port_id=1,
        service="ssl/http",
        port=443,
        cvss=None,
        epss=None,
        kev=False,
        tool_name="httpx_basic",
        parsed_output={"status_code": 200},
        base_confidence=policy["applicability_confidence"],
    )
    assert policy["decision"] == "SKIP"
    assert risk.severity != "critical"


def test_case_6_threat_intelligence_raises_priority_but_not_validation_state():
    low = evaluate_candidate(candidate(cvss=4.0, epss=0.01, kev=False))
    high = evaluate_candidate(candidate(cvss=9.8, epss=0.9, kev=True))
    assert high["validation_priority_score"] > low["validation_priority_score"]
    assert high["validation_state"] != "VALIDATED"


def test_case_7_no_compatible_tool_defers_without_tool():
    selected, evaluated = select_validation_candidates([candidate()], compatible_tool=False)
    assert selected == []
    assert evaluated[0]["decision"] == "DEFER"


def test_trace_export_contains_required_experiment_fields():
    row = evaluate_candidate(candidate())
    row["open_port_id"] = 9
    trace = build_cve_validation_trace([row], target_id=7)[0]
    required = {
        "target_id", "scan_run_id", "decision_id", "tool_task_id", "tool_result_id",
        "cve_id", "product", "detected_version", "match_type", "applicability_confidence",
        "cvss", "epss", "kev", "validation_priority_score", "decision",
        "validation_attempted", "validation_success", "final_validation_state", "evidence_confidence",
        "product_identity_confidence", "version_status", "validation_rank", "selected_for_validation",
        "tool_name", "final_cve_state",
    }
    assert required <= trace.keys()


def test_opencti_high_identity_unknown_version_ranks_top_two_without_stop():
    rows = [
        candidate("CVE-A", product="opencti", product_identity_confidence=0.92, cvss=9.8, epss=0.8, kev=True),
        candidate("CVE-B", product="opencti", product_identity_confidence=0.92, cvss=8.1, epss=0.4, kev=False),
        candidate("CVE-C", product="opencti", product_identity_confidence=0.92, cvss=5.4, epss=0.01, kev=False),
    ]
    selected, evaluated = select_validation_candidates(rows, limit=2)
    assert [item["cve_id"] for item in selected] == ["CVE-A", "CVE-B"]
    assert all(item["version_status"] == "UNKNOWN" for item in evaluated)
    assert selected[0]["validation_priority_score"] > selected[1]["validation_priority_score"]
    assert all(item["validation_state"] != "VALIDATED" for item in evaluated)


def test_high_epss_increases_priority_without_confirming_vulnerability():
    low = evaluate_candidate(candidate(epss=0.01, kev=False))
    high = evaluate_candidate(candidate(epss=0.9, kev=False))
    assert high["validation_priority_score"] > low["validation_priority_score"]
    assert high["validation_state"] == "VALIDATION_PENDING"


def test_kev_boosts_priority_and_is_eligible_for_top_n():
    no_kev = candidate("CVE-NO-KEV", epss=0.1, kev=False)
    kev = candidate("CVE-KEV", epss=0.1, kev=True)
    selected, evaluated = select_validation_candidates([no_kev, kev], limit=1)
    assert selected[0]["cve_id"] == "CVE-KEV"
    assert evaluated[0]["validation_priority_score"] > evaluated[1]["validation_priority_score"]


def test_weak_product_identity_does_not_expand_generic_http_to_product_cves():
    result = evaluate_candidate(
        candidate(product="unknown", match_type="service_only", product_identity_confidence=0.2)
    )
    assert result["decision"] == "SKIP"
    assert result["validation_state"] == "VERSION_UNRESOLVED"

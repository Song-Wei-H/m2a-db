from worker.cve_prioritizer import prioritize_cve_candidates


def candidate(cve, *, match_type="cpe_product_only", confidence=0.6, cvss=5.0, epss=0.01, kev=False):
    return {"cve_id": cve, "match_type": match_type, "match_confidence": confidence, "cvss_score": cvss, "epss": epss, "kev": kev}


def test_display_budget_is_strict_even_for_mandatory_candidates():
    rows = [
        candidate("CVE-KEV", kev=True),
        candidate("CVE-EXACT", match_type="exact_cpe_version", confidence=1.0),
        candidate("CVE-CRITICAL", confidence=0.9, cvss=9.8),
        candidate("CVE-EPSS", confidence=0.8, epss=0.5),
        candidate("CVE-OPTIONAL", cvss=8.0),
    ]

    selected, summary = prioritize_cve_candidates(rows, display_budget=1)

    assert len(selected) == 1
    assert summary["mandatory_candidates"] == 4
    assert summary["summarized_candidates"] == 4


def test_product_only_candidates_are_ranked_not_arbitrarily_truncated():
    rows = [candidate("CVE-LOW", cvss=4.0), candidate("CVE-HIGH", cvss=8.8), candidate("CVE-MID", cvss=6.0)]

    selected, summary = prioritize_cve_candidates(rows, display_budget=2)

    assert [row["cve_id"] for row in selected] == ["CVE-HIGH", "CVE-MID"]
    assert summary["total_candidates"] == 3
    assert summary["product_only_candidates"] == 3
    assert summary["summarized_candidates"] == 1


def test_duplicate_cve_keeps_strongest_evidence():
    rows = [
        candidate("CVE-SAME", confidence=0.6, cvss=9.0),
        candidate("CVE-SAME", match_type="exact_cpe_version", confidence=1.0, cvss=9.0),
    ]

    selected, summary = prioritize_cve_candidates(rows, display_budget=10)

    assert len(selected) == 1
    assert selected[0]["match_type"] == "exact_cpe_version"
    assert summary["total_candidates"] == 1

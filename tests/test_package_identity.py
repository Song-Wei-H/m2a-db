from worker.evidence_normalizer import normalize_tool_result
from worker.package_identity import extract_package_identities


def test_explicit_package_identity_is_normalized_for_osv():
    identities, status = extract_package_identities({
        "package_identity": {"ecosystem": "PyPI", "name": "urllib3", "version": "2.0.1"}
    })
    assert status == "ready"
    assert len(identities) == 1
    assert identities[0].ecosystem == "PyPI"
    assert identities[0].cache_key == extract_package_identities({
        "package_identity": {"ecosystem": "pypi", "name": "urllib3", "version": "2.0.1"}
    })[0][0].cache_key


def test_supported_purl_maps_to_osv_ecosystem_and_exact_version():
    identities, status = extract_package_identities({"purl": "pkg:pypi/urllib3@2.0.1"})
    assert status == "ready"
    assert identities[0].ecosystem == "PyPI"
    assert identities[0].name == "urllib3"
    assert identities[0].version == "2.0.1"


def test_service_product_and_version_are_never_guessed_as_package_identity():
    evidence = normalize_tool_result(
        "httpx_basic",
        {"status_code": 200, "webserver": "nginx", "version": "1.2.3"},
    )
    assert evidence == []
    identities, status = extract_package_identities({
        "details": {"product": "nginx", "version": "1.2.3"}
    })
    assert identities == []
    assert status == "not_provided"


def test_unsupported_or_conflicting_package_identity_fails_closed():
    identities, status = extract_package_identities({
        "package_identity": {"ecosystem": "unknown", "name": "x", "version": "1"}
    })
    assert identities == []
    assert status == "unsupported"

    identities, status = extract_package_identities({
        "package_identity": {
            "purl": "pkg:pypi/urllib3@2.0.1",
            "version": "2.0.2",
        }
    })
    assert identities == []
    assert status == "unsupported"


def test_normalized_evidence_carries_identity_and_never_raw_generic_version():
    evidence = normalize_tool_result(
        "httpx_basic",
        {
            "status_codes": [200],
            "urls": ["https://example.test"],
            "package_identity": {"ecosystem": "npm", "name": "demo", "version": "1.0.0"},
        },
    )
    assert evidence[0]["package_identity_status"] == "ready"
    assert evidence[0]["package_identities"][0]["name"] == "demo"

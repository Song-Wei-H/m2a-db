from worker.evidence_normalizer import normalize_tool_result
from worker.parsers.httpx_parser import parse_httpx_output


def test_httpx_explicit_version_is_preserved_as_observed_evidence():
    parsed = parse_httpx_output(
        '{"url":"https://target","status_code":200,"webserver":"nginx","version":"1.26.1"}'
    )

    evidence = normalize_tool_result("httpx_basic", parsed)[0]

    assert evidence["details"]["product"] == "nginx"
    assert evidence["details"]["version"] == "1.26.1"
    assert evidence["details"]["version_status"] == "observed"


def test_httpx_does_not_infer_version_from_product_or_title():
    parsed = parse_httpx_output(
        '{"url":"https://target","status_code":200,"title":"nginx 1.26.1","webserver":"nginx"}'
    )

    evidence = normalize_tool_result("httpx_basic", parsed)[0]

    assert evidence["details"]["version"] is None
    assert evidence["details"]["version_status"] == "not_observed"

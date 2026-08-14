from types import SimpleNamespace

import pytest

from app.tool_catalog import CANONICAL_ALLOWED_TOOLS
from worker.evidence_normalizer import normalize_tool_result
from worker.parsers.tool_result_parser import parse_tool_output


@pytest.mark.parametrize(
    ("tool_name", "evidence_type"),
    [
        ("tls_certificate", "tls_certificate"),
        ("http_security_headers", "http_security_posture"),
        ("dns_metadata", "dns_metadata"),
    ],
)
def test_remote_evidence_parser_and_normalizer(tool_name, evidence_type):
    parsed = parse_tool_output(
        tool_name,
        '{"observed": true, "certificate_validation": "not_performed"}',
        host="example.test",
        port=443,
    )
    evidence = normalize_tool_result(
        tool_name,
        parsed,
        raw_output="fixture",
        ctx=SimpleNamespace(host="example.test", port=443, service="https"),
        tool_result_id=42,
    )
    assert tool_name in CANONICAL_ALLOWED_TOOLS
    assert evidence[0]["evidence_type"] == evidence_type
    assert evidence[0]["confidence"] == 0.90
    assert evidence[0]["evidence_ref"] == "tool_result:42"
    assert evidence[0]["details"]["observed"] is True

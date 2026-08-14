from worker.evidence_normalizer import normalize_tool_result
from worker.parsers.nmap_parser import parse_nmap_result


def test_nmap_open_ports_are_normalized_with_result_provenance():
    parsed = parse_nmap_result(
        "443/tcp open ssl/http nginx",
        host="10.56.67.13",
    )

    evidence = normalize_tool_result(
        "nmap_service",
        parsed,
        raw_output="443/tcp open ssl/http nginx",
        tool_result_id=126,
    )

    assert len(evidence) == 1
    assert evidence[0]["evidence_type"] == "network_service"
    assert evidence[0]["evidence_ref"] == "tool_result:126"
    assert evidence[0]["details"]["port"] == 443
    assert evidence[0]["details"]["product"] == "nginx"

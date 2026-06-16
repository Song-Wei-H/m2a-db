from worker.parsers.nmap_parser import parse_nmap_output, parse_nmap_result


def test_nmap_parser_extracts_ports():
    raw = "443/tcp open https nginx 1.25\n22/tcp open ssh OpenSSH 9.6"

    ports = parse_nmap_output(raw)
    parsed = parse_nmap_result(raw)

    assert ports[0]["port"] == 443
    assert ports[0]["protocol"] == "tcp"
    assert ports[0]["service"] == "https"
    assert ports[0]["product"] == "nginx"
    assert ports[0]["version"] == "1.25"
    assert parsed["parser_success"] is True
    assert parsed["ports"][0]["port"] == 443
    assert parsed["open_ports"][1]["service"] == "ssh"


def test_nmap_parser_malformed_input():
    parsed = parse_nmap_result("not nmap output")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "no nmap ports parsed"


def test_nmap_parser_empty_input():
    parsed = parse_nmap_result("")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "empty input"

from worker.parsers.dirb_parser import parse_dirb_output


def test_dirb_parser_extracts_paths():
    parsed = parse_dirb_output("+ https://target/admin (CODE:200|SIZE:1234)")

    assert parsed["parser_success"] is True
    assert parsed["paths"][0]["discovered_path"] == "/admin"
    assert parsed["paths"][0]["status_code"] == 200
    assert parsed["paths"][0]["size"] == 1234


def test_dirb_parser_malformed_input():
    parsed = parse_dirb_output("not dirb output")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "no dirb paths parsed"


def test_dirb_parser_empty_input():
    parsed = parse_dirb_output("")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "empty input"

from worker.parsers.httpx_parser import parse_httpx_output


def test_httpx_parser_extracts_json_service():
    raw = '{"url":"https://target","status_code":200,"title":"Welcome","content_length":1234,"tech":["nginx"],"webserver":"nginx"}'

    parsed = parse_httpx_output(raw)

    assert parsed["parser_success"] is True
    service = parsed["services"][0]
    assert service["url"] == "https://target"
    assert service["status_code"] == 200
    assert service["title"] == "Welcome"
    assert service["content_length"] == 1234
    assert service["technologies"] == ["nginx"]
    assert service["webserver"] == "nginx"


def test_httpx_parser_extracts_plain_line():
    parsed = parse_httpx_output("https://target [403] [Forbidden]")

    assert parsed["parser_success"] is True
    assert parsed["services"][0]["url"] == "https://target"
    assert parsed["services"][0]["status_code"] == 403
    assert parsed["services"][0]["title"] == "Forbidden"


def test_httpx_parser_malformed_input():
    parsed = parse_httpx_output("not httpx output")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "no httpx services parsed"


def test_httpx_parser_empty_input():
    parsed = parse_httpx_output("")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "empty input"

from worker.parsers.httpx_parser import parse_httpx_output


def test_httpx_parser_extracts_json_service():
    raw = '{"url":"https://target","status_code":200,"title":"Welcome","content_length":1234,"tech":["nginx"],"webserver":"nginx","version":"1.26.1"}'

    parsed = parse_httpx_output(raw)

    assert parsed["parser_success"] is True
    service = parsed["services"][0]
    assert service["url"] == "https://target"
    assert service["status_code"] == 200
    assert service["title"] == "Welcome"
    assert service["content_length"] == 1234
    assert service["technologies"] == ["nginx"]
    assert service["webserver"] == "nginx"
    assert service["version"] == "1.26.1"


def test_httpx_parser_keeps_json_observation_when_startup_banner_is_appended():
    raw = (
        '{"url":"http://10.56.66.119:18080/","status_code":200,'
        '"title":"M2A Mode B Lab Target","webserver":"nginx/1.29.0",'
        '"tech":["Nginx:1.29.0"]}\n'
        "    __    __  __       _  __\n"
        "\t\tprojectdiscovery.io\n"
        "[\\x1b[34mINF\\x1b[0m] Current httpx version v1.9.0 (outdated)\n"
    )

    parsed = parse_httpx_output(raw, success=True, host="10.56.66.119", port=18080)

    assert parsed["parser_success"] is True
    assert parsed["entry_count"] == 1
    assert parsed["entries"][0]["url"] == "http://10.56.66.119:18080/"
    assert parsed["entries"][0]["status_code"] == 200
    assert parsed["entries"][0]["title"] == "M2A Mode B Lab Target"


def test_httpx_parser_still_rejects_banner_without_observation():
    raw = "httpx scanner startup\nprojectdiscovery.io\n[WRN] dashboard disabled"

    parsed = parse_httpx_output(raw, success=True)

    assert parsed["parser_success"] is False
    assert parsed["entry_count"] == 0
    assert parsed["reason"] == "httpx banner only"


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

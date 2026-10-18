from worker.parsers.nuclei_parser import parse_nuclei_output


def test_nuclei_parser_extracts_json_finding():
    raw = '{"template-id":"cves/2024/CVE-XXXX","info":{"severity":"high","name":"Test CVE"},"matched-at":"https://target","matcher-name":"body","type":"https"}'

    parsed = parse_nuclei_output(raw, host="target")

    assert parsed["parser_success"] is True
    assert parsed["findings"][0]["template_id"] == "cves/2024/CVE-XXXX"
    assert parsed["findings"][0]["severity"] == "high"
    assert parsed["findings"][0]["url"] == "https://target"
    assert parsed["findings"][0]["host"] == "target"
    assert parsed["findings"][0]["protocol"] == "https"
    assert parsed["findings"][0]["matcher_name"] == "body"


def test_nuclei_parser_extracts_text_finding():
    parsed = parse_nuclei_output("[cves/2024/CVE-XXXX] [https] [high] https://target [body]")

    assert parsed["parser_success"] is True
    assert parsed["findings"][0]["template_id"] == "cves/2024/CVE-XXXX"
    assert parsed["findings"][0]["severity"] == "high"


def test_nuclei_parser_malformed_input():
    parsed = parse_nuclei_output("not nuclei output")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "no nuclei findings parsed"


def test_nuclei_parser_empty_input():
    parsed = parse_nuclei_output("")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "empty input"


def test_nuclei_parser_explicit_completed_no_finding_is_not_an_error():
    raw = "[INF] Templates loaded for current scan: 1\n[INF] Targets loaded for current scan: 1\n[INF] Scan completed in 11ms. No results found."
    parsed = parse_nuclei_output(raw, success=True, host="127.0.0.1", port=18080)
    assert parsed["parser_success"] is True
    assert parsed["scan_outcome"] == "NO_FINDING"
    assert parsed["finding_count"] == 0


def test_nuclei_parser_timeout_and_error_are_not_no_finding():
    timed_out = parse_nuclei_output("command timeout", success=False)
    failed = parse_nuclei_output("process failed", success=False)
    assert timed_out["scan_outcome"] == "TIMEOUT"
    assert failed["scan_outcome"] == "ERROR"
    assert timed_out["parser_success"] is False
    assert failed["parser_success"] is False

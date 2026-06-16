from worker.parsers.mysql_info_parser import parse_mysql_info_output


def test_mysql_info_parser_extracts_mysql_info():
    raw = """
Server version: 8.0.36 MySQL Community Server
Protocol version: 10
Capabilities: SSL,CONNECT_WITH_DB,PLUGIN_AUTH
Auth plugin: caching_sha2_password
"""

    parsed = parse_mysql_info_output(raw)

    assert parsed["parser_success"] is True
    assert parsed["mysql"]["version"] == "8.0.36 MySQL Community Server"
    assert parsed["mysql"]["protocol_version"] == "10"
    assert "SSL" in parsed["mysql"]["capabilities"]
    assert parsed["mysql"]["auth_plugin"] == "caching_sha2_password"


def test_mysql_info_parser_malformed_input():
    parsed = parse_mysql_info_output("not mysql info")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "no mysql info parsed"


def test_mysql_info_parser_empty_input():
    parsed = parse_mysql_info_output("")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "empty input"

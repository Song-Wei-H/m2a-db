from worker.parsers.ssh_enum_parser import parse_ssh_enum_output


def test_ssh_enum_parser_extracts_algorithms():
    raw = """
22/tcp open ssh OpenSSH 9.6 protocol 2.0
| ssh2-enum-algos:
|   kex_algorithms:
|     curve25519-sha256
|   server_host_key_algorithms:
|     ssh-ed25519
|   encryption_algorithms:
|     chacha20-poly1305@openssh.com
|   mac_algorithms:
|     hmac-sha2-256
"""

    parsed = parse_ssh_enum_output(raw)

    assert parsed["parser_success"] is True
    assert parsed["ssh_algorithms"]["kex_algorithms"] == ["curve25519-sha256"]
    assert parsed["ssh_algorithms"]["host_key_algorithms"] == ["ssh-ed25519"]
    assert parsed["ssh_algorithms"]["encryption_algorithms"] == ["chacha20-poly1305@openssh.com"]
    assert parsed["ssh_algorithms"]["mac_algorithms"] == ["hmac-sha2-256"]


def test_ssh_enum_parser_malformed_input():
    parsed = parse_ssh_enum_output("not ssh enum output")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "no ssh enum data parsed"


def test_ssh_enum_parser_empty_input():
    parsed = parse_ssh_enum_output("")

    assert parsed["parser_success"] is False
    assert parsed["reason"] == "empty input"

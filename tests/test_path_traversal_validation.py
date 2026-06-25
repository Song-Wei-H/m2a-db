import pytest

from app.security.dangerous_chars import assert_safe_string, contains_dangerous_chars


@pytest.mark.parametrize(
    "value",
    [
        "../etc/passwd",
        "..\\windows",
        "safe/../escape",
        "%2e%2e%2fetc",
        "%2e%2e%5cwindows",
        "name\x00value",
        "name\u202evalue",
        "line\u0001break",
    ],
)
def test_path_traversal_and_control_characters_rejected(value):
    assert contains_dangerous_chars(value) is True
    with pytest.raises(ValueError):
        assert_safe_string(value, "target")


def test_safe_plain_value_allowed():
    assert assert_safe_string("app.example.test", "target") == "app.example.test"

"""Reject shell metacharacters — LLM must never pass commands through."""

from __future__ import annotations

import re
import unicodedata

# ; | & ` $ ( ) > < newline carriage-return
DANGEROUS_PATTERN = re.compile(r"[;|&`$()><\r\n]")
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\.|%2e|%2f|%5c)",
    re.IGNORECASE,
)
FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "command",
        "cmd",
        "shell",
        "raw_command",
        "exec",
        "argv",
        "script",
        "payload",
        "bash",
        "sh",
    }
)


def contains_dangerous_chars(value: str) -> bool:
    if "\x00" in value:
        return True
    if DANGEROUS_PATTERN.search(value) is not None:
        return True
    if PATH_TRAVERSAL_PATTERN.search(value) is not None:
        return True
    return any(unicodedata.category(char) in {"Cc", "Cf"} for char in value)


def assert_safe_string(value: str, field_name: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must not be empty")
    if contains_dangerous_chars(cleaned):
        raise ValueError(
            f"{field_name} contains forbidden characters "
            "(; | & ` $ ( ) > < newline, path traversal, or control characters)"
        )
    return cleaned


def reject_forbidden_keys(payload: dict) -> None:
    for key in payload:
        if key.lower() in FORBIDDEN_FIELD_NAMES:
            raise ValueError(f"Forbidden field not allowed in LLM output: {key!r}")

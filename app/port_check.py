"""Check whether a TCP port is in use (Windows-friendly PID lookup)."""

from __future__ import annotations

import re
import socket
import subprocess
import sys


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def find_listening_pids(port: int) -> list[int]:
    """Return PIDs listening on *port* (best-effort; Windows uses netstat)."""
    if sys.platform == "win32":
        return _find_pids_windows(port)
    return _find_pids_unix(port)


def _find_pids_windows(port: int) -> list[int]:
    try:
        output = subprocess.check_output(
            ["netstat", "-ano"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    pids: list[int] = []
    pattern = re.compile(rf":{port}\s+.*LISTENING\s+(\d+)\s*$", re.IGNORECASE)
    for line in output.splitlines():
        match = pattern.search(line.strip())
        if match:
            pids.append(int(match.group(1)))
    return sorted(set(pids))


def _find_pids_unix(port: int) -> list[int]:
    try:
        output = subprocess.check_output(
            ["ss", "-ltnp"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    pids: list[int] = []
    needle = f":{port}"
    for line in output.splitlines():
        if needle not in line or "LISTEN" not in line.upper():
            continue
        for match in re.finditer(r"pid=(\d+)", line):
            pids.append(int(match.group(1)))
    return sorted(set(pids))


def resolve_api_port(
    preferred: int = 8000,
    fallback: int = 8001,
    *,
    allow_fallback: bool = True,
) -> tuple[int, list[int]]:
    """
    Pick a port for the API server.

    Returns (chosen_port, pids_blocking_preferred).
    If preferred is busy and fallback is allowed/free, returns fallback.
    Raises OSError if no port is available.
    """
    preferred_pids = find_listening_pids(preferred) if is_port_in_use(preferred) else []

    if not preferred_pids:
        return preferred, []

    if not allow_fallback:
        raise OSError(
            f"Port {preferred} is already in use (PID: {', '.join(map(str, preferred_pids))})"
        )

    if is_port_in_use(fallback):
        fallback_pids = find_listening_pids(fallback)
        raise OSError(
            f"Port {preferred} in use (PID: {', '.join(map(str, preferred_pids))}); "
            f"fallback port {fallback} also in use "
            f"(PID: {', '.join(map(str, fallback_pids))})"
        )

    return fallback, preferred_pids

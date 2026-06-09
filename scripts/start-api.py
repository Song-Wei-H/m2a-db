#!/usr/bin/env python3
"""Start FastAPI with port check (avoid WinError 10013 from duplicate uvicorn)."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.port_check import find_listening_pids, is_port_in_use, resolve_api_port


def main() -> int:
    parser = argparse.ArgumentParser(description="Start M2A FastAPI (uvicorn)")
    parser.add_argument("--port", type=int, default=8000, help="Preferred port (default: 8000)")
    parser.add_argument("--fallback-port", type=int, default=8001, help="Fallback if preferred busy")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--reload", action="store_true", default=True)
    parser.add_argument("--no-fallback", action="store_true", help="Fail instead of using fallback port")
    parser.add_argument("--no-reload", action="store_true")
    args = parser.parse_args()

    try:
        port, blocked_pids = resolve_api_port(
            args.port,
            args.fallback_port,
            allow_fallback=not args.no_fallback,
        )
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(
            "Stop the existing process or pick another port, e.g.\n"
            f"  netstat -ano | findstr :{args.port}\n"
            "  taskkill /PID <PID> /F",
            file=sys.stderr,
        )
        return 1

    if blocked_pids:
        print(
            f"WARNING: port {args.port} is in use (PID: {', '.join(map(str, blocked_pids))}). "
            f"Starting API on port {port} instead."
        )
    elif is_port_in_use(port):
        pids = find_listening_pids(port)
        print(f"ERROR: port {port} is in use (PID: {', '.join(map(str, pids))}).", file=sys.stderr)
        return 1
    else:
        print(f"Starting API on http://{args.host}:{port}")

    os.environ["API_PORT"] = str(port)

    python = ROOT / ".venv" / "Scripts" / "python.exe"
    if not python.exists():
        python = Path(sys.executable)

    cmd = [
        str(python),
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        args.host,
        "--port",
        str(port),
    ]
    if args.reload and not args.no_reload:
        cmd.append("--reload")

    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())

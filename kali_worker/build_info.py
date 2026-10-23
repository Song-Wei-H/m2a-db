"""Stable digest for the Worker entrypoint and its replay safety control."""
from __future__ import annotations

import hashlib
from pathlib import Path


def worker_build_sha256() -> str:
    worker_dir = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for filename in ("app.py", "build_info.py", "replay_ledger.py"):
        digest.update(filename.encode("ascii"))
        digest.update(b"\0")
        digest.update((worker_dir / filename).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()

"""Fixed, harmless execution emulation used only by the isolated GADE lab."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_ID = "gade-controlled-python-execution-v1"
MARKER_NAME = "execution-marker.json"
IDENTITY = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        return 2
    run_id, case_id, request_id, marker_arg = argv
    if not all(IDENTITY.fullmatch(value) for value in (run_id, case_id, request_id)):
        return 2
    marker_path = Path(marker_arg)
    if marker_path.name != MARKER_NAME or not marker_path.parent.is_dir():
        return 2
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    # Deliberately small deterministic computation: no user-supplied code, input,
    # command, network access, or system modification.
    result = sum((6, 7)) * 3
    if result != 39:
        return 1
    marker = {
        "script_id": SCRIPT_ID,
        "script_sha256": source_hash,
        "run_id": run_id,
        "test_case_id": case_id,
        "request_id": request_id,
        "executed_at_utc": utc_now(),
        "result": result,
        "marker": "GADE-L3-CONTROLLED-EXECUTION-COMPLETE",
    }
    temporary = marker_path.with_name(f".{marker_path.name}.{request_id}.tmp")
    try:
        payload = (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, marker_path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    print(json.dumps({"script_id": SCRIPT_ID, "result": result}, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

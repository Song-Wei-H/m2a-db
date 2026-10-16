from __future__ import annotations

import importlib.util
import json
import os
import uuid
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "lab/mode-b-target/validate_l3_target.py"
SPEC = importlib.util.spec_from_file_location("validate_l3_target", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_evidence_save_retries_transient_windows_replace_lock(monkeypatch):
    scratch = Path(os.environ.get("GADE_L3_TEST_SCRATCH", Path(__file__).parents[1]))
    scratch.mkdir(parents=True, exist_ok=True)
    output = scratch / f"_l3-evidence-save-{uuid.uuid4().hex}.json"
    client = MODULE.Client("http://10.56.66.119:18080", "RUN-TEST", output)
    original_replace = os.replace
    attempts = 0

    def transient_replace(source, destination):
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            raise PermissionError("simulated transient Windows file lock")
        return original_replace(source, destination)

    try:
        output.write_text('{"prior": true}\n', encoding="utf-8")
        monkeypatch.setattr(MODULE.os, "replace", transient_replace)
        monkeypatch.setattr(MODULE.time, "sleep", lambda _: None)
        client.save("RUNNING", {"checkpoint": "PASS"}, "2026-10-15T00:00:00Z")

        saved = json.loads(output.read_text(encoding="utf-8"))
        assert attempts == 3
        assert saved["result"] == "RUNNING"
        assert saved["checks"]["checkpoint"] == "PASS"
        assert not list(scratch.glob(output.name + ".*.tmp"))
    finally:
        output.unlink(missing_ok=True)
        for temp in scratch.glob(output.name + ".*.tmp"):
            temp.unlink(missing_ok=True)


def test_evidence_save_preserves_last_checkpoint_when_lock_persists(monkeypatch):
    scratch = Path(os.environ.get("GADE_L3_TEST_SCRATCH", Path(__file__).parents[1]))
    scratch.mkdir(parents=True, exist_ok=True)
    output = scratch / f"_l3-evidence-save-{uuid.uuid4().hex}.json"
    previous = '{"prior": true}\n'
    client = MODULE.Client("http://10.56.66.119:18080", "RUN-TEST", output)
    attempts = 0

    def persistent_lock(_source, _destination):
        nonlocal attempts
        attempts += 1
        raise PermissionError("simulated persistent Windows file lock")

    try:
        output.write_text(previous, encoding="utf-8")
        monkeypatch.setattr(MODULE.os, "replace", persistent_lock)
        monkeypatch.setattr(MODULE.time, "sleep", lambda _: None)
        try:
            client.save("RUNNING", {"checkpoint": "PASS"}, "2026-10-15T00:00:00Z")
        except OSError as error:
            assert "after 8 attempts" in str(error)
        else:
            raise AssertionError("persistent replacement lock should fail closed")

        assert attempts == 8
        assert output.read_text(encoding="utf-8") == previous
        assert len(list(scratch.glob(output.name + ".*.tmp"))) == 1
    finally:
        output.unlink(missing_ok=True)
        for temp in scratch.glob(output.name + ".*.tmp"):
            temp.unlink(missing_ok=True)

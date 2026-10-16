import importlib.util
import json
import os
import shutil
import uuid
from pathlib import Path

import pytest


DRIVER_PATH = (
    Path(__file__).resolve().parents[1]
    / "experiments"
    / "gade-seven-level-v1"
    / "l2-action"
    / "run_l2_d7_d1.py"
)
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://reset_test:reset_test@127.0.0.1:1/reset_test")
SPEC = importlib.util.spec_from_file_location("gade_l2_driver_under_test", DRIVER_PATH)
assert SPEC and SPEC.loader
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


RUN_ID = "a0a7077dd35d"


@pytest.fixture
def tmp_path():
    path = Path(__file__).resolve().parents[1] / ".tmp-reset-gate-tests" / uuid.uuid4().hex
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def write_reset(tmp_path: Path, case: str = "D7", **updates) -> Path:
    case_id = f"GADE-L2-{case}-{RUN_ID}-RESET"
    record = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "case_id": case_id,
        "request_id": case_id + "-request",
        "reset_started_utc": "2026-10-15T07:00:00+00:00",
        "reset_completed_utc": "2026-10-15T07:00:01+00:00",
        "reset_status": "VERIFIED",
        "target_response": {"status": "reset", "active_sessions": 0, "test_case_id": case_id},
        "state_verification": {
            "passed": True,
            "status": "reset",
            "active_sessions": 0,
            "test_case_id": case_id,
        },
    }
    record.update(updates)
    path = tmp_path / f"lab-reset-{case.lower()}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


@pytest.mark.parametrize("case", ["D7", "D1"])
def test_verified_reset_evidence_is_accepted(tmp_path, case):
    path = write_reset(tmp_path, case)
    result = DRIVER.validate_reset_gate_evidence(tmp_path, RUN_ID, case)
    assert result["file"] == path.name
    assert len(result["sha256"]) == 64


def test_missing_reset_evidence_blocks_case(tmp_path):
    with pytest.raises(RuntimeError, match="evidence is missing"):
        DRIVER.validate_reset_gate_evidence(tmp_path, RUN_ID, "D7")


def test_failed_reset_record_blocks_case(tmp_path):
    write_reset(tmp_path, reset_status="FAILED")
    with pytest.raises(RuntimeError, match="is not verified"):
        DRIVER.validate_reset_gate_evidence(tmp_path, RUN_ID, "D7")


def test_reset_must_match_run_and_case_identity(tmp_path):
    write_reset(tmp_path, run_id="ffffffffffff")
    with pytest.raises(RuntimeError, match="run identity mismatch"):
        DRIVER.validate_reset_gate_evidence(tmp_path, RUN_ID, "D7")


def test_reset_must_prove_zero_active_sessions(tmp_path):
    write_reset(tmp_path, state_verification={
        "passed": True, "status": "reset", "active_sessions": 1,
        "test_case_id": f"GADE-L2-D7-{RUN_ID}-RESET",
    })
    with pytest.raises(RuntimeError, match="state verification failed"):
        DRIVER.validate_reset_gate_evidence(tmp_path, RUN_ID, "D7")


def test_reset_timestamps_must_be_ordered_utc(tmp_path):
    write_reset(tmp_path, reset_started_utc="bad-time")
    with pytest.raises(RuntimeError, match="UTC timestamps are invalid"):
        DRIVER.validate_reset_gate_evidence(tmp_path, RUN_ID, "D7")

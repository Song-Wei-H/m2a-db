"""Persistent Worker replay ledger tests; no Worker or Target Action is run."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.execution_governance import parameter_hash
from kali_worker.replay_ledger import ReplayLedgerError, claim_authorization_once


def claim(path, *, request_id="request-a", request_hash="a" * 64):
    claim_authorization_once(
        str(path), authorization_id=812, task_id=901, request_id=request_id,
        request_hash=request_hash,
    )


def test_first_claim_succeeds_exact_replay_and_parameter_mutation_fail(tmp_path):
    database = tmp_path / "worker-replay.sqlite3"
    original_request = {"authorization_parameters": {"target": "127.0.0.1", "path": "/backup/"}}
    mutated_request = {"authorization_parameters": {"target": "127.0.0.1", "path": "/other/"}}
    claim(database, request_hash=parameter_hash(original_request))
    with pytest.raises(ReplayLedgerError) as exact:
        claim(database, request_hash=parameter_hash(original_request))
    assert exact.value.reason_code == "AUTHORIZATION_ALREADY_CLAIMED"

    with pytest.raises(ReplayLedgerError) as mutated:
        claim(database, request_hash=parameter_hash(mutated_request))
    assert mutated.value.reason_code == "AUTHORIZATION_REPLAY_CONFLICT"

    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT authorization_id, task_id, request_id, request_hash FROM worker_authorization_claims"
        ).fetchall()
    assert rows == [("812", "901", "request-a", parameter_hash(original_request))]


def test_missing_relative_memory_and_unavailable_paths_fail_closed(tmp_path):
    for path in (None, "", ":memory:", "relative.sqlite3", str(tmp_path / "missing" / "ledger.sqlite3")):
        with pytest.raises(ReplayLedgerError) as error:
            claim_authorization_once(path, authorization_id=812, task_id=901,
                                     request_id="request-a", request_hash="a" * 64)
        assert error.value.reason_code == "REPLAY_LEDGER_UNAVAILABLE"


def _child_claim_command():
    return textwrap.dedent("""
        import sys
        import time
        from kali_worker.replay_ledger import ReplayLedgerError, claim_authorization_once

        path, start = sys.argv[1], float(sys.argv[2])
        time.sleep(max(0, start - time.time()))
        try:
            claim_authorization_once(path, authorization_id=944, task_id=955,
                                     request_id="cross-process", request_hash="c" * 64)
            print("CLAIMED")
        except ReplayLedgerError as error:
            print(error.reason_code)
    """)


def _spawn_claim(database, start_at, project_root):
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(project_root)
    return subprocess.Popen(
        [sys.executable, "-c", _child_claim_command(), str(database), str(start_at)],
        cwd=project_root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def test_concurrent_independent_processes_and_restart_allow_only_one_claim(tmp_path):
    database = tmp_path / "worker-replay.sqlite3"
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    start_at = time.time() + 1.0
    processes = [_spawn_claim(database, start_at, project_root) for _ in range(2)]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, stderr
        results.append(stdout.strip())
    assert sorted(results) == ["AUTHORIZATION_ALREADY_CLAIMED", "CLAIMED"]

    # A new Python process models a Worker process restart using the same durable file.
    restarted = _spawn_claim(database, time.time(), project_root)
    stdout, stderr = restarted.communicate(timeout=15)
    assert restarted.returncode == 0, stderr
    assert stdout.strip() == "AUTHORIZATION_ALREADY_CLAIMED"


def test_concurrent_threads_claim_only_once(tmp_path):
    database = tmp_path / "worker-replay.sqlite3"
    def attempt(_index):
        try:
            claim_authorization_once(str(database), authorization_id=966, task_id=977,
                                     request_id="thread-race", request_hash="d" * 64)
            return "CLAIMED"
        except ReplayLedgerError as error:
            return error.reason_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    assert outcomes.count("CLAIMED") == 1
    assert outcomes.count("AUTHORIZATION_ALREADY_CLAIMED") == 7

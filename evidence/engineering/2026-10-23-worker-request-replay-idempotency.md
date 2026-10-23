# GADE Worker Request Replay / Idempotency — Offline Verification

- Handoff ID: `GADE-WORKER-REPLAY-20261023`
- Date: 2026-10-23
- Classification: `OFFLINE / STUB / CROSS-PROCESS SQLITE`; no real Worker process, Target, Action, PostgreSQL connection, Docker, formal experiment, merge, or push.
- Worktree: branch `home-advanced-policy`, HEAD `c88aba51581b141e63b23280454b601edf63dbd8`.
- Formal A/B/C samples remain `0/0/0`.

## Before / prior evidence

The immediately preceding offline observation is preserved in `2026-10-23-execution-authorization-replay-toctou.md`, SHA-256 `94f066bece3616fcb54fa884815e6662b6965cb975ad9e21c91e5d9469ce4b40` (recomputed and matched). It recorded the same stubbed `/execute` request accepted twice, invoking the stub twice. That historical observation was not changed or rerun as a real Action.

The worktree was already dirty before this stage. Its existing changes to `app/execution_governance.py`, `app/execution_trace.py`, `kali_worker/app.py`, `tests/test_execution_authorization.py`, `tests/test_gade_advanced_home_contract.py`, `worker/task_poller.py`, and the untracked autonomous-policy / target-identity files and `evidence/` were preserved. No reset, stash, checkout, commit, merge, or push was used.

## Implementation

- Added `kali_worker/replay_ledger.py`. For every request carrying an `authorization_id`, the Worker requires an absolute file-backed `KALI_WORKER_REPLAY_DB_PATH`; relative paths, `:memory:`, missing parent directories, and database errors fail closed. The parent is operator-managed; the ledger does not create it.
- Before any handler is called, SQLite `BEGIN IMMEDIATE` and a primary-key insert on `authorization_id` atomically persist the authorization ID, Task ID, Request ID, full-request SHA-256, and claim timestamp. Raw request parameters are not stored. The transaction uses a bounded busy timeout and `synchronous=FULL`.
- First claim succeeds. Exact duplicate returns `AUTHORIZATION_ALREADY_CLAIMED`; same authorization with a different Task/Request/hash returns `AUTHORIZATION_REPLAY_CONFLICT`; unavailable storage returns `REPLAY_LEDGER_UNAVAILABLE`. None reaches the handler.
- The ledger is a dispatch replay guard, not a second authorization system or cryptographic caller/grant verifier. M2A remains the authority source. A crash after durable claim but before handler start consumes the one-shot claim; there is intentionally no automatic retry or cached-result replay. This provides at-most-once dispatch, not exactly-once completion.
- `home-lab/start-kali-worker.sh` now configures `/home/kali/.local/state/m2a-worker/execution-replay.sqlite3` under `umask 077`, creating the parent directory on Worker startup. The script was not run or deployed.
- Added `kali_worker/build_info.py` so the Worker digest includes `app.py`, `build_info.py`, and `replay_ledger.py`; M2A dispatch uses the same calculation. Current digest: `0cbc2ad7bc412e1f3b23145eecb8698d599a5e9f1054431cccaf94386675b414`.
- The Worker receipt reports `worker_replay_claim=PERSISTED_SINGLE_USE`. `worker/remote_runner.py` rejects native governed receipts without this claim, and `app/execution_trace.py` marks such a trace `PARTIAL`.

## Tests and outcomes

Final focused command (process-only dead DB sentinel; the tests did not connect to it):

```powershell
python -m pytest -q -rs -p no:cacheprovider `
  tests/test_worker_replay_ledger.py `
  tests/test_execution_authorization.py `
  tests/test_gade_target_identity.py `
  tests/test_task_poller_postgresql_locking.py `
  tests/test_phase3_batch2_contract.py tests/test_phase3_batch3_contract.py tests/test_phase3_batch4_contract.py `
  tests/test_gade_advanced_home_contract.py tests/test_gade_autonomous_action_policy.py `
  tests/test_execution_trace.py tests/test_remote_runner.py tests/test_remote_runner_observability.py `
  tests/test_task_poller_learning_feedback.py
```

Result: **117 passed, 1 skipped, 0 failed, 1 deprecation warning**. The skip is the opt-in PostgreSQL trace integration test. The warning is Starlette TestClient/httpx. No database connection occurred.

| Scenario | Result | Verification level |
|---|---|---|
| First valid stubbed Worker request | PASS; durable claim marker returned | In-process TestClient / stub handler |
| Exact replay | PASS; rejected and handler called once total | In-process TestClient / stub handler |
| Parameter digest changed under same authorization | PASS; `AUTHORIZATION_REPLAY_CONFLICT` | Offline ledger unit test |
| Concurrent duplicate HTTP requests | PASS; one handler invocation | In-process TestClient + shared SQLite file |
| Two independent Python processes racing on one authorization | PASS; one `CLAIMED`, one rejected | Cross-process local SQLite |
| New Python process after simulated Worker restart | PASS; prior authorization still rejected | Cross-process local SQLite |
| Missing, relative, memory-only, or unavailable ledger | PASS; fail closed | Offline unit test; missing-config endpoint test |
| Missing Worker receipt replay claim | PASS; M2A runner rejects | Fake HTTP response |
| Missing receipt replay claim in Trace | PASS; `PARTIAL` | Offline trace fixture |
| Health build digest matches M2A dispatch digest | PASS | Offline health test |

The exact final focused result was followed by one separate health test (`1 passed, 1 warning`). A supplementary non-Home-Lab profile suite returned `43 passed, 1 failed, 1 warning`: the unrelated, unmodified `lab/mode-b-target/l3_execution_task.py` hashes to `0ed8cbd9f252a7b6dad9aa387a57b0ec2c3b7f5c718741327256e384771ff23e`, while its existing L3 contract test expects `b6d8391432ad8f0f993a51c2c35e13d86354f3d0220c3e1c71d69e82a5f164bb`. The file is clean in Git and was not changed here; this mismatch is outside replay scope and is not counted as a replay-control failure.

An initial mixed-profile diagnostic also produced failures because Home-Lab environment settings were applied to legacy-profile tests and the first subprocess test helper contained invalid `-c` syntax. The helper was corrected and profiles were tested separately; the final scoped suite above is the acceptance result. A standalone health-test collection initially lacked the required process-only `DATABASE_URL` sentinel; rerunning with the dead sentinel passed.

## Deployment limits

- Same-host process concurrency and process-restart persistence were validated against one temporary SQLite file. This is not proof of an actual Kali deployment, disk durability under VM rollback, or multi-host coordination. Multiple Worker hosts do not share this local file and would require shared transactional state before claiming fleet-wide at-most-once dispatch.
- The home startup script only configures the path; the Kali Worker was not started or modified. The actual `/home/kali/...` file, owner/mode, Worker build, and `/health` were not verified. `LIVE_DEPLOYMENT=NOT_TESTED`.
- No real Worker/Target Action ran. PostgreSQL concurrency, revocation, authenticated/signed grants, and claim-to-handler crash recovery remain outside this stage. A retry after a timeout is intentionally rejected, so an outcome may remain uncertain rather than risk executing twice.
- `git diff --check` passed. A shell syntax check was attempted with the available Windows `bash.exe`, which returned access denied; no startup script was executed. No commit/merge/push.

## Files touched in this stage

`kali_worker/replay_ledger.py`, `kali_worker/build_info.py`, `kali_worker/app.py`, `worker/remote_runner.py`, `worker/task_poller.py`, `app/execution_trace.py`, `home-lab/start-kali-worker.sh`, `tests/test_worker_replay_ledger.py`, `tests/test_gade_target_identity.py`, `tests/test_execution_trace.py`, `tests/test_remote_runner_observability.py`, `tests/test_task_poller_learning_feedback.py`, `tests/test_gade_l2_action.py`, `tests/test_gade_l3_action.py`, and `tests/test_kali_worker_app.py`.

Source/test SHA-256 values and this report's digest are in the adjacent `.sha256` manifest. The result is offline candidate validation only; it does not mark the deployed replay boundary resolved.

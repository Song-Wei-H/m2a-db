# GADE Grant Replay / TOCTOU Offline Verification

- Handoff ID: `GADE-GRANT-TOCTOU-20261023`
- Date: 2026-10-23
- Tier: `MOCK / OFFLINE`; no PostgreSQL, Worker process, Target, Docker, or Live Action was used.
- Worktree: branch `home-advanced-policy`, HEAD `c88aba51581b141e63b23280454b601edf63dbd8`.
- Formal samples: unchanged (`0/0/0`). No merge, push, or commit.

## Findings

`app/execution_governance.py` creates a one-use `ExecutionAuthorization` and binds target record ID, action ID, canonical parameters/hash, execution identity, template version, validation tier, scope, expiry, and approval metadata. `ExecutionAuthorization` has `execution_limit` and `consumed_count`, but no revocation field or revoke API.

`worker/task_poller.py::_claim_task` locks the pending `ToolTask` and its authorization, then checks target/action binding, expiry, and remaining use before incrementing `consumed_count` and conditionally claiming the task. This round added a fail-closed check that loads the current `Target` and rejects a missing Target or a changed `scope` before consuming the grant. This only checks the value observed during claim; the Target row is not locked by this new read, and no claim-to-dispatch or post-claim revalidation was proven. It therefore does not close every TOCTOU window.

Worker-side `target_identity_binding` revalidation is exercised only for the synthetic discovery path with a `FakeVerifier`; there is no configured production verifier or persistent Worker replay ledger. Reposting the exact same authorized Worker request twice was accepted twice by the in-process endpoint and invoked a stub handler twice. This is an observed replay-control boundary gap, not an actual Target Action: the handler was replaced with a test stub and no external request or state change occurred.

## Cases

| Case | Expected | Observed | Result / tier |
|---|---|---|---|
| Valid grant, matching target/action/scope, first claim | Claim once | Claim succeeded and consumed count became 1 | PASS — Mock claim path |
| Same consumed grant used for a second task | Reject replay | Second claim rejected; task remained pending | PASS — Mock claim path |
| Expired grant | Reject | Claim rejected without consuming | PASS — Mock claim path |
| Revoked grant | Reject | Not representable: model has no revocation state/API | BLOCKED — schema/runtime capability absent |
| Target/action mismatch at claim | Reject | Claim rejected without consuming | PASS — Mock claim path |
| Target scope changed before claim | Reject | New scope equality check rejected without consuming | PASS — Mock claim path |
| Target/scope changes after successful claim, before dispatch | Reject | Not exercised against a database/Worker transaction; current check is claim-time only | NOT_VERIFIED — TOCTOU remains |
| Identity fingerprint changes at Worker revalidation | Reject before handler | Fake verifier mismatch rejected; handler call count 0 | PASS — Mock + in-process TestClient |
| Worker request changes action, target, or canonical parameters | Reject before handler | All three substitutions rejected; handler call count 0 | PASS — Mock + in-process TestClient |
| Two claimers contend for one grant | At most one claim | One claim succeeded in an asyncio fake row-lock model | PASS — Mock only; PostgreSQL concurrency unverified |
| Exact Worker request replayed with same authorization/request ID | Reject duplicate | Both requests accepted and the stub handler was invoked twice | `BOUNDARY_VIOLATION` — Mock observation; no real action |

## Tests

Command (run from the worktree with the isolated `.venv`; process-only env included `GADE_HOME_LAB_EXPLORATORY=1`, policy version `gade-home-autonomous-policy-v1`, `PYTHONDONTWRITEBYTECODE=1`, worktree `PYTHONPATH`, `.venv\tmp` for `TEMP`/`TMP`, and dead sentinel `DATABASE_URL=postgresql+asyncpg://127.0.0.1:1/offline_test_only`):

```powershell
.\.venv\Scripts\python.exe -m pytest -q -rs -p no:cacheprovider tests/test_execution_authorization.py tests/test_gade_target_identity.py tests/test_task_poller_postgresql_locking.py tests/test_phase3_batch2_contract.py tests/test_phase3_batch3_contract.py tests/test_phase3_batch4_contract.py tests/test_gade_advanced_home_contract.py tests/test_gade_autonomous_action_policy.py tests/test_execution_trace.py tests/test_remote_runner.py tests/test_remote_runner_observability.py
```

Result: `102 passed, 1 skipped, 0 failed, 1 warning`. The skipped test requires an opt-in PostgreSQL connection; the SQL locking test compiles/asserts SQL but does not prove concurrent PostgreSQL behavior. The warning is Starlette TestClient/httpx deprecation. `git diff --check` passed.

Test additions/changes in this stage are limited to `worker/task_poller.py`, `tests/test_execution_authorization.py`, and additions to the already-dirty `tests/test_gade_target_identity.py`. The scope check is the only production-code change in this stage. Existing dirty files and evidence were preserved.

## State and limits

- No PostgreSQL connection or schema write.
- No Worker or Target action; no Docker, Trust Root, formal experiment, or Live test.
- No revocation behavior is available to validate.
- Same-request replay at the Worker is not prevented by the current evidence. A durable, shared single-use/idempotency mechanism and a defined revocation contract are required before claiming replay/revocation protection across processes.
- Claim-time scope equality is a narrow improvement, not proof against concurrent post-check changes. Independent Target identity attestation remains unconfigured; Mock identity tests are not Live proof.
- Existing dirty worktree was retained; this task was not committed, merged, or pushed.

See canonical M2A Known Issues, Build History, and Runbook entries for this handoff ID.

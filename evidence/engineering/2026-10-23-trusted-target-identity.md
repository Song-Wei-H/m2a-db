# GADE Trusted Target Identity — 2026-10-23

Handoff marker: `GADE-TARGET-ID-20261023`

## Scope and worktree

- Repository: `C:\Users\黃崧瑋\Documents\Codex\m2a-gade-policy`
- Branch: `home-advanced-policy`
- Base/current HEAD: `c88aba51581b141e63b23280454b601edf63dbd8`
- Status: existing dirty candidate preserved; this task added no commit, merge, push, formal sample, or Live action. The original home `experiment/gade-seven-level-v1` worktree was not modified.
- Existing prior-policy uncommitted files remain in this worktree. Current identity work adds/updates the files listed under “Implementation.”

## Trust source and dataflow

- The Target database row contains a target record ID, endpoint, and scope, but no independently verified target identity.
- `LlmToolProposal` does not permit an AI-provided `target_identity` field; an unknown field fails schema validation. Policy pins expected label `gade-l2-t1078`, but that label alone is not proof.
- The code defines a `TargetIdentityVerifier` interface whose proof must be derived from an independent authenticated target-side source. No production verifier or attestation key/source is configured: `get_configured_target_identity_verifier()` returns `None`.
- Authorization therefore DENYs by default if a production verifier is missing, unavailable, stale, malformed, or mismatched. The isolated tests inject an explicitly marked Fake verifier only; this does not establish a real target identity.
- On a test-only ALLOW, identity proof is bound to the exact target record, expected identity, endpoint/port/scope, verifier/fingerprint, evidence hash, action, proposal/grant ID, execution identity, parameter hash, and grant expiry. The binding is stored in the existing `AuthorizationDecision.contract_snapshot` and covered by its record hash.
- Immediately before the one candidate Worker handler, Worker checks the bound Grant and calls its independently configured verifier again. Missing verifier, stale or malformed binding, identity change, or mismatch is rejected before handler invocation and logged. The deployed/default path has no verifier and remains DENY.
- Failures are represented in the existing authorization decision snapshot with reason codes and `target_identity_check=FAIL`; the Worker rejection path emits a structured `target_identity_check` event. Persistence/trace behavior was checked in code and unit contracts, not against a live database or execution trace.

## Implementation

- `app/target_identity.py`: `TargetIdentityVerifier`, `VerifiedTargetIdentity`, `verify_registered_target_identity`, `validate_target_identity_proof`, `build_grant_identity_binding`, `validate_binding_record`, `target_identity_binding_for_grant`, `verify_runtime_target_identity`.
- `app/autonomous_action_policy.py`: the existing `evaluate_autonomous_action` now requires a valid externally supplied proof, pins a 60-second maximum age, and requires pre-handler runtime recheck in the versioned policy.
- `app/execution_governance.py`: `propose_and_authorize` and `evaluate_and_authorize` verify identity before policy ALLOW, recheck during grant construction, store the grant-bound identity snapshot, and fail closed when unavailable.
- `app/execution_trace.py`: `execution_request` carries only the identity binding recovered from the hash-verified decision and exact grant; `trace_tool_result` flags missing/mismatched binding.
- `kali_worker/app.py`: `ExecuteRequest` accepts the binding; `/execute` independently re-verifies it immediately before `lab.synthetic_node_discovery.v1` handler dispatch and rejects on failure.
- `home-lab/action-contracts/autonomous-policy-v1.json`: pins identity proof age, runtime recheck, and grant-binding semantics. No other L4–L7 Action was enabled or modified for execution.
- Tests: `tests/test_gade_target_identity.py` adds TID-01…08; policy/contract regression files remain part of the pre-existing dirty candidate and were included in the focused test run.

## TID test results

All results below are **MOCK/OFFLINE or in-process TestClient only**. There was no real Worker process, network request, database, target, or Live Action.

| ID | Expected | Actual | Result / Evidence |
|---|---|---|---|
| TID-01 | ALLOW when policy and identity proof match | ALLOW; exact identity binding linked to grant and execution request | PASS — `tests/test_gade_target_identity.py::test_tid_01_matching_mock_identity_allows_and_binds_identity_to_grant` (MOCK) |
| TID-02 | DENY on identity mismatch | DENY `TARGET_IDENTITY_MISMATCH`; no grant | PASS — `...::test_tid_02_identity_mismatch_denies_without_grant` (MOCK) |
| TID-03 | DENY when identity source is missing | DENY `TARGET_IDENTITY_UNVERIFIED`; no grant | PASS — `...::test_tid_03_missing_verifier_denies_without_grant` (MOCK) |
| TID-04 | DENY a Proposal self-claim | Pydantic rejects unknown `target_identity` field | PASS — `...::test_tid_04_proposal_cannot_self_declare_target_identity` (OFFLINE schema test) |
| TID-05 | Runtime DENY after target replacement | in-process Worker `/execute` returns `TARGET_IDENTITY_CHANGED`; handler call count 0 | PASS — `...::test_tid_05_worker_runtime_denies_target_replacement_after_grant` (simulated verifier / in-process) |
| TID-06 | DENY expired proof | DENY `TARGET_IDENTITY_EVIDENCE_EXPIRED`; no grant | PASS — `...::test_tid_06_expired_identity_evidence_denies_without_grant` (MOCK) |
| TID-07 | Fail closed if verifier unavailable | DENY `TARGET_IDENTITY_VERIFIER_UNAVAILABLE`; no grant | PASS — `...::test_tid_07_verifier_failure_denies_without_grant` (MOCK) |
| TID-08 | No Worker Action after identity rejection | Worker rejects `TARGET_IDENTITY_UNVERIFIED`; handler call count 0 | PASS — `...::test_tid_08_worker_rejects_without_invoking_action_when_no_live_verifier` (in-process TestClient) |

## Verification

- Focused pytest command covered the TID, autonomous policy, advanced-home contract, and L4 Worker contract files: **44 passed, 1 Starlette/httpx deprecation warning**. Test DB URL was a non-routable placeholder; tests use fakes and in-process TestClient. No full-repository test run was attempted; the older 78 passed / 6 failed baseline remains unresolved and is not superseded.
- Python AST parse: 8 affected Python files PASS.
- Policy JSON parse: PASS.
- `git diff --check`: PASS.
- No real identity verifier, Target-side attestation, Worker deployment, target request, PostgreSQL write, Live execution, or formal sample was performed. Trusted identity and Live readiness remain **BLOCKED / NOT_VERIFIED** until an operator-pinned independent verifier is implemented and validated.
- Obsidian local notes were updated/read back in the four existing canonical files; Sync status was not observable and remains `NOT_VERIFIED`.

## Evidence integrity

This report and the implementation/test files are covered by `2026-10-23-trusted-target-identity.sha256`. The manifest records SHA-256 for the report, relevant code/tests/policy artifact, and the four updated canonical notes. Re-hash verification is required before handoff.


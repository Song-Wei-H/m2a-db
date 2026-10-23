# GADE autonomous policy candidate — engineering evidence

- Date: 2026-10-23 (Asia/Taipei)
- Classification: HOME_LAB_EXPLORATORY engineering / offline contract only; not a research sample.
- Isolated worktree: `C:\Users\黃崧瑋\Documents\Codex\m2a-gade-policy`
- Branch / base: `home-advanced-policy` at `c88aba51581b141e63b23280454b601edf63dbd8`
- Original home worktree: `C:\Users\黃崧瑋\Documents\Codex\2026-08-22\new-chat\m2a-gade-home`, branch `experiment/gade-seven-level-v1`, HEAD `4147a9d32d9be3a7d2c9a715884f853bda900a55`; its pre-existing dirty files remain untouched.
- No merge, push, formal experiment, Worker request, Target action, or Live validation was performed.

## Action-contract review

Source contracts are `home-lab/action-contracts/advanced-synthetic-v1.json` and `home-lab/action-contracts/l4-synthetic-role-lease-v1.json`. The policy candidate pins their SHA-256 digests. Shared target constraints are `127.0.0.1:18080`, scope `127.0.0.1/32`, IP target, the contract's `gade-l2-t1078` identity label, and each action's canonical execution identity. The app `Target` record has no separate target-identity field; the candidate therefore binds the label to the pinned contract plus exact endpoint/scope/action identity tuple. This is not independent Live target-identity proof and must remain a deployment blocker until the target-side identity is verified through a trusted source.

| Action | Depth | Fixed effect / precondition from contract | Candidate decision |
|---|---:|---|---|
| `lab.synthetic_role_lease.v1` | 4 | Authenticated fixed test session; reversible synthetic role lease, no OS privilege change | DENY |
| `lab.synthetic_canary_access.v1` | 5 | Read non-secret canary identifier | DENY |
| `lab.simulated_visibility_comparison.v1` | 5 | Compare Lab-only visibility mode; do not change real controls | DENY |
| `lab.synthetic_node_discovery.v1` | 6 | Read fixed two-node synthetic topology; no session/state mutation | ALLOW only on exact policy match |
| `lab.synthetic_node_session.v1` | 6 | Fixed logical-node session; separate source/destination event files | DENY |
| `lab.synthetic_collection.v1` | 7 | Select fixed synthetic record set | DENY |
| `lab.local_c2_simulation.v1` | 7 | Local NOOP heartbeat/acknowledgement; no external C2 | DENY |
| `lab.synthetic_receiver_transfer.v1` | 7 | Fixed synthetic digest to logical Lab receiver; no external network | DENY |
| `lab.reversible_impact_simulation.v1` | 7 | Reversible Lab-only impact flag; no real service interruption | DENY |

The source contract also requires a fixed POST, authenticated test session, and run-ID header; canonical Action parameters remain fixed by the existing Action Contract. L6 logical nodes and L7 logical receiver remain simulations, not separate network hosts/services. ATT&CK references remain analogies rather than claims of real attack capability.

## Policy behavior

Candidate manifest: `home-lab/action-contracts/autonomous-policy-v1.json`, id `gade-home-autonomous-policy-v1`, status `CANDIDATE_DISABLED_BY_DEFAULT`. It is not enabled by default. For the sole ALLOW candidate, the existing Governance path must also see the exact policy opt-in, `HOME_LAB_EXPLORATORY`, active `m2a-attack-depth-v1` target authorization profile configured by `operator-ui`, depth 6, exact target/scope/type, canonical action identity/parameters, unexpired profile, a 1–60 second grant TTL, and integrity-checked `registered_target` plus matching `decision_input` Evidence. Success issues only the existing ExecutionAuthorization with one use and bounded expiry.

Any missing/drifted source contract, unmatched contract metadata, unsupported Action, wrong depth/scope/identity, bad TTL, missing/tampered Evidence, disabled policy, or expired/missing profile DENYs before grant creation. The eight non-selected Actions—including the L4 lease—are explicit DENY. This deterministic DENY overrides legacy Approval for those policy-managed Actions; legacy Approval remains unchanged outside this candidate policy scope. Direct `propose_and_authorize` calls cannot bypass the policy with a caller-supplied ALLOW object; the helper re-evaluates the candidate and requires integrity-checked Evidence.

## Verification

Final command (local isolated worktree, no external target):

```powershell
$env:GADE_HOME_LAB_EXPLORATORY='1'
& 'C:\Users\黃崧瑋\Documents\Codex\m2a-db\.venv\Scripts\python.exe' -m pytest --tb=no -q tests/test_gade_autonomous_action_policy.py tests/test_gade_advanced_home_contract.py tests/test_gade_home_l4_contract_worker.py
```

Result: **36 passed, 0 failed**. Coverage includes the one bounded L6 policy ALLOW through existing Governance, disabled-policy DENY, all non-selected Action DENYs (including the L4 role lease), depth/scope/profile/TTL/Evidence failures, tampered Evidence, previous Approval not overriding DENY, and direct-helper fail-closed behavior. The tests use in-memory fake sessions; the ALLOW result is not a persisted or executed grant.

`git diff --check`: PASS. Policy JSON parse: PASS. No complete repository-wide pytest suite was run.

Obsidian: the existing four canonical notes (Build History, Known Issues, Runbook, Experiment Design) were incrementally appended and read back as valid UTF-8, each with a unique new section and expected backlinks. Local readback PASS; Obsidian Sync completion remains NOT_VERIFIED.

An earlier focused run exposed that a supplied legacy human approval could override a DENY. That bypass was corrected by evaluating the action policy before the approval/grant path; final tests verify it does not issue authorization. A subsequent manifest-consistency test caught a missing L6 path in the policy manifest; that metadata was aligned to the source contract before the final passing run.

## Changed files and SHA-256

| File | SHA-256 |
|---|---|
| `app/execution_governance.py` | `6b0fab1c9170be134b5f013646a15df9623440ec1ee02671278b02fd25e5a75d` |
| `app/autonomous_action_policy.py` | `ae22475c5126bc4dceded26b5c15dcb7c221857c931f0119bd3d7797088e88b6` |
| `home-lab/action-contracts/autonomous-policy-v1.json` | `ed05c69419d7b4c1508f47a449e79bd23ad79c61076a16f40fce6a62ce054fdd` |
| `tests/test_gade_autonomous_action_policy.py` | `6b28e75cae72d8096e819e6390270d0fec4ef6bf7c2f99fc955c51a0790e0a7e` |
| `tests/test_gade_advanced_home_contract.py` | `f423e5f6e6899609005de8ff3f05762c0d7caed8e3969aee2c02c96a3e5ae923` |

The source contract digests pinned by the candidate are `b4db3697666eb15deaa1c8fe27abcd39af8a2e5b087ca4018f4a35082afca212` (advanced actions) and `6950692eb437c73d4d58690f05bd3dcb5ed788553db5eb38e44013ca3b1792b5` (L4 role lease).

## Remaining blockers

- Candidate has not been enabled in a deployed runtime; no Live or Worker verification.
- `gade-l2-t1078` is not independently stored/attested in the `Target` model; verify from trusted Target-side identity before any Live use.
- No Action beyond read-only synthetic L6 discovery has been converted; all others remain DENY.
- Full repository regression and Obsidian Sync completion remain NOT_VERIFIED. ChatGPT round-trip remains pending until the single browser test is sent and read back.

# M2A capability and GADE thesis audit — 2026-08-13

## Evidence boundary

- Repository: `Song-Wei-H/m2a-db`
- Audited commit: `9e7651535d36dd8fd8d28403a0a715852758e7b3`
- Local validation after the changes below: `303 passed`; frontend production build succeeded.
- This is code and automated-test evidence. It is not a deployed-environment, authorized-lab, or thesis experiment result.

## Corrected defect

The approval center previously received only task IDs, so a reviewer could not inspect the target, scope, tool, or proposal rationale. Approval/rejection rationale was not persisted. The repair:

- returns target, scope, tool, proposal rationale, gate rationale, and creation time;
- requires a non-blank human decision rationale and stores it separately from the gate rationale;
- records the LLM proposal rationale on the immutable task record;
- adds migration `024_approval_decision_audit.sql` and regression tests;
- enables the frontend approval dialog only after a rationale is entered.

This improves informed human review but does not authenticate the approver.

## Capability status

| Capability | Evidence level | Status |
|---|---|---|
| Tool allowlist and fixed command templates | code + automated tests | implemented/tested |
| `shell=False` governed worker execution | code + automated tests | implemented/tested |
| Approval state gate | code + automated tests | implemented/tested; no deployed E2E evidence |
| Informed approval context and rationale audit | code + automated tests | repaired/tested; migration not applied to a live DB |
| Scope checks, path validation, duplicate prevention, max rounds | code + automated tests | implemented/tested; scenario coverage is not exhaustive |
| JSON/HTML/PDF report generation and frontend access | code + automated tests + frontend build | implemented/tested; renderer/runtime E2E not performed |
| ATT&CK mapping quality | deterministic mapping code/tests | implementation exists; no labeled-corpus precision/recall/F1 |
| Prompt-injection resistance | architectural controls only | not adversarially validated |
| Formal GADE RQ1–RQ3 experiment | none | not performed |

## Remaining high-priority gaps

1. Add real approver authentication/authorization; `approved_by` remains client supplied.
2. Bind approval to a versioned digest of exact task parameters and policy version.
3. Add approval expiry, execution window, concurrency/rate ceilings, and a complete approval-history endpoint.
4. Run migration 024 and a controlled API → database → poller → worker → result → report E2E test in an authorized lab.
5. Build the versioned Governance Proposal Set, Evidence Mapping Set, and Decision Replay Set described by the thesis.
6. Execute prompt/tool-output manipulation tests and measure routing/decision escape, not merely parser acceptance.
7. Add CI, release/version policy, and deployment documentation. No GitHub Actions workflow or license was present during this audit.

## Notion thesis V2 comparison

The thesis correctly states that no formal experimental or quantitative results exist. It should retain that boundary. Its maturity table and Appendix D can be updated as follows:

- approval pre-execution enforcement, duplicate prevention, max-round controls, and report endpoints now have code/test evidence;
- report artifacts and a frontend are present in commit `9e76515`, unlike the older Vault audit at `ff60d6d`;
- informed human approval was incomplete at audit start and is repaired only in the current uncommitted worktree;
- ATT&CK mapping accuracy, prompt-injection effectiveness, all-path deployed E2E enforcement, and RQ1–RQ3 results remain unverified.

Do not convert `303 passed` or a successful frontend build into research outcome metrics. They support implementation correctness for covered cases only.

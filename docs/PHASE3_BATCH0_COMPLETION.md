# Phase 3 Batch 0 Completion

Date: 2026-08-20  
Baseline: `e905435` (Phase 3 Audit + Migration Matrix)  
Scope: `http_security_headers.collect.v1`, `nuclei.safe_scan.v1` only

## Canonical identity mapping

| Action | Tier | Template | Execution identity | Canonical execution unit |
|---|---:|---|---|---|
| `http_security_headers.collect.v1` | 1 | `http_security_headers_v2` | `builtin:http-security-headers:head-root:user-agent=M2A-Worker/1:connection=close:timeout=10:tls-verify=false:redirect=false:body=false:v2` | Canonical root URL plus fixed HEAD collector contract |
| `nuclei.safe_scan.v1` | 2 | `nuclei_safe_v2` | `argv:nuclei:-u:{canonical_url}:-severity:critical,high:-rl:5:-timeout:5:-retries:0:-no-color:v2` | Canonical root URL plus exact immutable argv |

Both parameter contracts bind target, host, scheme, port, protocol, service,
path and canonical URL. Header also binds collector behavior; Nuclei also binds
the complete argv. Caller/LLM risk metadata is not an authoritative tier input.

## Legacy closure

The sole production ToolTask writer adapts any legacy creation attempt for
these two tools into DecisionProposal -> Registry -> ExecutionAuthorization
before inserting a pending task. Existing governed Auto Loop and
`/tools/llm-propose` paths remain governed directly. Poller and remote Worker
both reject either migrated tool without authorization. Action, target,
canonical parameter hash, execution identity and template version mismatches
fail closed.

This closes the Batch 0 paths identified for Auto Loop, Manual Decision,
approved LLM recommendation, `/tools/llm-propose`, analysis pipeline, direct
writer helpers, dispatcher/poller and Worker. Retest does not select either
Batch 0 action and remains outside this migration.

## Migration and validation evidence

- `initdb/028_phase3_batch0_identity.sql` is additive and idempotent.
- Historical authorizations are not backfilled or rewritten.
- Migration was applied twice to PostgreSQL 16 with `ON_ERROR_STOP`; both runs passed.
- Live Registry -> enabled CommandTemplate join returned exactly one v2 template per action.
- Full pytest: `345 passed`.
- Real PostgreSQL concurrent claims: `[True, False]`; final `consumed_count=1`.
- Frontend: `tsc -b && vite build` passed.
- Existing report lineage regression remains covered by the full suite; current
  ToolTask/Result linkage uses investigation/action/task IDs while historical
  results remain separate.

## Remaining risks and Batch 1 readiness

- Batch 0 relies on synchronized deployment of API/poller, DB migration and
  Kali Worker; mixed-version deployment intentionally fails closed.
- The first migration attempt exposed stale field names in the audit wording
  (`command_argv`/`allowed_placeholders`). PostgreSQL authority is
  `argv_template`/`allowed_fields`; the failed transaction made no partial
  identity update, and the migration was corrected and revalidated.
- No Tier 3 action was created. No Batch 1 action was changed.
- Batch 1 may begin only after separate human approval.

# Phase 3 Batch 2 Completion

Date: 2026-08-20  
Baseline: `bfb5a813efe08d678d164515f4566919a696316f`  
Scope: `nmap.service_fingerprint.v1` only

## Canonical contract

`nmap.service_fingerprint.v1` is Discovery Tier 1 with template
`nmap_service_v2` and exact Worker argv `nmap -sV {target}`. The authorization
binds target/address, no port override, Nmap default port set, service/version
detection, Nmap-default host discovery and retry behavior, no scripts, and the
Worker process timeout of 180 seconds. Target, port-scope, parameter, template
or execution-identity drift fails closed.

## Post-nmap decision boundary

Initial Target creation, human retest and all centralized ToolTask creation now
adapt nmap through DecisionProposal -> Registry -> ExecutionAuthorization before
inserting a task. The nmap result analysis pipeline still selects legacy or
migrated downstream tools according to existing rules. It was not expanded.

For already migrated downstream actions (Header, Nuclei, DNS and TLS), both the
analysis path and Auto Loop use the canonical writer/task generator. Therefore:

```text
nmap evidence -> decision -> migrated action request
-> proposal -> governance -> authorization -> ToolTask
```

HTTPx, SSH, MySQL and dirb remain pending migration and retain their existing
legacy behavior. They were not changed in Batch 2.

## Validation evidence

- Migration 030 applied twice to PostgreSQL 16: PASS.
- Registry -> ValidationAction -> enabled `nmap_service_v2`: PASS.
- Full backend suite: `359 passed`.
- Real PostgreSQL nmap concurrent claims: `[True, False]`, `consumed_count=1`.
- Frontend `tsc -b && vite build`: PASS.
- No real Target scan was executed.
- Three historical pending unbound nmap tasks were not backfilled and are now
  fail-closed because nmap is a protected action.

## Remaining risks

- `-sV` inherits Nmap default port-set, host-discovery and retry behavior; the
  contract prohibits caller overrides but does not claim those defaults are
  identical across every future Nmap version. Worker/tool version pinning is a
  reproducibility follow-up.
- API/poller, migration and Worker must be deployed together; mixed versions
  intentionally fail closed.
- Batch 3 was not started and requires separate human authorization.

# Phase 3 Validation Registry / Tier Migration Matrix

> Phase 3 Batches 0–4 were implemented and validated on 2026-08-20 through
> migrations 028–032. See `PHASE3_BATCH0_COMPLETION.md` through
> `PHASE3_BATCH3_COMPLETION.md`; Batch 4 is covered by migration 032 and
> `tests/test_phase3_batch4_contract.py`. This matrix is now the completion and
> residual-gap record. Batch 5 (`dirb_safe`) has not been approved or migrated.

Baseline: `5317aef` (`feat: add authorization-first governance slice`)

Status: Batches 0–4 complete; eight actions are authorization-first. Batch 5 remains a separate human decision.

## Authority rules

- Tier belongs to a versioned action/capability, never to a tool name or caller/LLM risk value.
- Caller/LLM `risk_level` may influence presentation or queue priority only.
- A migrated action is complete only when Registry action, template/version, canonical parameters, M2A authorization, and Worker execution identity describe the same operation.
- Historical approval is not ExecutionAuthorization and must not be promoted automatically.
- Unknown or mismatched identity fails closed. No Tier 3 action is claimed without evidence of an existing operation and explicit human-authorization semantics.
- ExecutionAuthorization is server-internal. No public API allows a client or LLM to mint an execution grant.

## Action inventory and migration matrix

| Tool | Action ID | Tier | Template version | Current state |
|---|---|---:|---|---|
| `dns_metadata` | `dns.metadata_collect.v1` | 0 | `dns_metadata_v2` | Migrated; bounded builtin DNS metadata contract |
| `http_security_headers` | `http_security_headers.collect.v1` | 1 | `http_security_headers_v2` | Migrated; bounded HEAD-only builtin contract |
| `tls_certificate` | `tls.certificate_collect.v1` | 1 | `tls_certificate_v2` | Migrated; bounded TLS handshake contract |
| `nmap_service` | `nmap.service_fingerprint.v1` | 1 | `nmap_service_v2` | Migrated; fixed `nmap -sV` identity |
| `httpx_basic` | `httpx.web_probe.v1` | 1 | `httpx_web_probe_v2` | Migrated; canonical URL and fixed probe identity |
| `ssh-enum` | `ssh.algorithms_enum.v1` | 1 | `ssh_algorithms_enum_v2` | Migrated; exact bounded NSE identity |
| `mysql-info` | `mysql.server_info.v1` | 1 | `mysql_server_info_v2` | Migrated; exact no-auth metadata identity |
| `nuclei_safe` | `nuclei.safe_scan.v1` | 2 | `nuclei_safe_v2` | Migrated; bounded severity/rate/timeout identity |
| `dirb_safe` | `dirb.content_discovery.v1` (candidate) | 2 (candidate) | Not defined | Legacy/unmigrated; not part of authorization-first coverage |

Aliases `httpx`, `nuclei`, and `dirb` are input normalization aliases, not separate executable actions. Historical alias rows remain provenance and must not be rewritten.

## Current creation and enforcement inventory

| Path | Current behavior | Residual requirement |
|---|---|---|
| `POST /targets`, retest, `scan_run_dispatcher.py` | Shared ToolTask writer adapts migrated nmap work through Registry governance | Keep transactional and duplicate-prevention regressions covered. |
| Analysis, Decision, auto-loop and recommendation paths | Migrated tools converge on shared writer/dispatcher governance; Registry tier is authoritative | Do not reintroduce direct migrated-tool creation bypasses. |
| `/tools/llm-propose` | Accepts a schema-bound proposal; server resolves action/tier and creates internal authorization when policy allows | Do not add a client-mintable grant endpoint. |
| Worker poller | Every `PROTECTED_ACTION_TOOLS` task requires a matching, valid, unconsumed authorization; claim is atomic | Keep real PostgreSQL replay/concurrency coverage. |
| Kali Worker `/execute` | Reconstructs migrated action parameters and rejects action/tool/identity/hash mismatch | Add cryptographic caller/grant authentication separately. |
| `dirb_safe` | Remains on the explicitly unmigrated legacy path | Requires a separately approved bounded Batch 5 contract. |

The execution identity and parameter hash bind components to one deterministic
contract, but they are not a cryptographic authentication mechanism. Worker
caller authentication or signed grants, resolved-IP scope pinning outside
NDR-controlled deployments, and API authentication/RBAC remain separate gaps.

## Migration completion ledger

### Batch 0 — completed by migration 028

- `http_security_headers.collect.v1`
- `nuclei.safe_scan.v1`

### Batch 1 — completed by migration 029

- `dns.metadata_collect.v1`
- `tls.certificate_collect.v1`

### Batch 2 — completed by migration 030

- `nmap.service_fingerprint.v1`

### Batch 3 — completed by migration 031

- `httpx.web_probe.v1`

### Batch 4 — completed by migration 032

- `ssh.algorithms_enum.v1`
- `mysql.server_info.v1`

### Batch 5 — not approved or migrated

- `dirb.content_discovery.v1`

Reason: highest remaining request-volume and governance uncertainty. Define a
bounded wordlist, request/rate ceiling, timeout, canonical URL, exact execution
identity, and escalation policy before enabling authorization-first execution.

## Tests required for every migrated batch

1. Registry action resolves to one enabled template/version and one exact Worker execution identity.
2. Canonical target/port/service/protocol representation is deterministic; substitutions are rejected.
3. Caller/LLM low risk cannot lower Registry tier or change authorization policy.
4. Missing, expired, consumed, target/action/parameter/template-mismatched authorization cannot be claimed.
5. Two concurrent claimers consume a single-use authorization at most once using a real PostgreSQL integration test.
6. Every creation path for the migrated action either creates DecisionProposal -> Authorization -> ToolTask or fails closed; static direct-creation test included.
7. Kali Worker rejects tool-only legacy requests for the migrated action and verifies exact identity before DNS/target execution where practical.
8. ToolResult preserves investigation/action/task lineage; report labels current pending versus historical result.
9. Existing Risk, Learning, MITRE, Normalizer, CVE enrichment and report contracts pass regression.
10. Migration is additive/idempotent and creates no authorization for historical approval/task rows.

## Remaining human decision gate

- Reason: `dirb_safe` has the highest remaining request-volume and governance uncertainty.
- Required contract before migration: bounded wordlist, request/rate ceiling, timeout, canonical URL, exact execution identity, escalation policy, and regression tests.
- Current decision: keep it explicitly legacy and exclude it from the eight-action authorization-first claim.
- Requested future decision: approve, revise, or reject a separately evidenced Batch 5 proposal. No Batch 5 implementation is authorized by this record.

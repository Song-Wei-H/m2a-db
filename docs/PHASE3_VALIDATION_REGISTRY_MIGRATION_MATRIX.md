# Phase 3 Validation Registry / Tier Migration Matrix

> Batch 0 was implemented and validated on 2026-08-20. See
> `PHASE3_BATCH0_COMPLETION.md`. This matrix remains the audit authority for
> later batches; no Batch 1 migration is implied.

Baseline: `5317aef` (`feat: add authorization-first governance slice`)

Status: audit and migration proposal only. No action migration is authorized by this document.

## Authority rules

- Tier belongs to a versioned action/capability, never to a tool name or caller/LLM risk value.
- Caller/LLM `risk_level` may influence presentation or queue priority only.
- A migrated action is complete only when Registry action, template/version, canonical parameters, M2A authorization, and Worker execution identity describe the same operation.
- Historical approval is not ExecutionAuthorization and must not be promoted automatically.
- Unknown or mismatched identity fails closed. No Tier 3 action is proposed without evidence of an existing operation that requires it.

## Action inventory and migration matrix

| Tool | Proposed action ID | Phase | Tier | Authoritative tier rationale | Template / canonical parameters | Worker actual execution identity | Current state and legacy path |
|---|---|---|---:|---|---|---|---|
| `dns_metadata` | `dns.metadata_collect.v1` | Discovery | 0 | Bounded observational DNS metadata; no content mutation or broad enumeration | Current `dns_metadata_v1` is symbolic `remote-evidence {target}`. Canonical: target; runtime-derived resolved addresses must be recorded as output, not caller parameters. Proposed identity: `builtin:dns_metadata:v1`. | Resolve A/AAAA, optional PTR, `getfqdn`; no subprocess. Worker resolves target before handler. | Not registered as an action. LLM/dispatcher can create a legacy executable ToolTask. No historical tasks in live DB. |
| `nmap_service` | `nmap.service_fingerprint.v1` | Discovery | 1 | Active service/version probing of one authorized target | Existing `nmap_service`: `nmap -sV {target}`; canonical: target. Existing template and Worker argv match for IP/host target. | `argv:nmap:-sV:{target}` | Largest legacy surface: target creation, retest, scan-run dispatcher and other decision paths create ToolTask directly. Live DB: 53 tasks, 3 pending, none action-bound. |
| `httpx_basic` | `httpx.web_probe.v1` | Discovery | 1 | Active HTTP request, redirects and technology/title collection | Existing template hardcodes `http://{target}:{port}` and omits `-json`; canonical should be target, port, service and derived URL. Requires a new versioned template rather than silent reuse. | `httpx -u {derived_url} -json -title -tech-detect -status-code -follow-redirects` | Risk/analysis pipeline can create direct not-required ToolTask; dispatcher/task generator are not action-bound. Live DB: 48 canonical plus one historical alias task. |
| `tls_certificate` | `tls.certificate_collect.v1` | Discovery | 1 | One active TLS handshake; bounded but network-active | Current `tls_certificate_v1` is generic `remote-evidence {target} {port}`. Canonical: target and port; service/protocol may be context only. Replace or version symbolic template as `builtin:tls_certificate:v1`. | TCP connect, TLS client handshake, SNI target, timeout 10, `CERT_NONE`, certificate SHA-256 and negotiated metadata; no subprocess. | Not action-bound. Reachable through proposal/decision paths. No historical tasks in live DB. |
| `http_security_headers` | `http_security_headers.collect.v1` | Discovery | 1 | One active HTTP HEAD request with no body/redirect; bounded network effect | Registry exists, but `http_security_headers_v1` is generic `remote-evidence`; canonical authorization has target, port, protocol, service. Strict Phase 3 equality requires a versioned builtin template/identity contract. | `builtin:http_security_headers:v1`: HEAD `/`, fixed user-agent, no redirect/body, timeout 10, TLS verification disabled for collection. | Partially migrated. Dispatcher/task generator create authorization, but direct Decision/LLM ToolTask paths can create unbound tasks and Worker does not globally require authorization for this discovery tool. No live historical tasks. |
| `ssh-enum` | `ssh.algorithms_enum.v1` | Discovery | 1 | Active protocol metadata enumeration; bounded NSE script | Existing template fixes port 22 and uses `{{host}}`; canonical should be target and selected port. Requires version bump. | `nmap --script ssh2-enum-algos -p {port-or-22} {target}` | Analysis pipeline can create direct not-required task. LLM validator does not expose it, but generic dispatcher/config can. Live DB: 3 tasks, none action-bound. |
| `mysql-info` | `mysql.server_info.v1` | Discovery | 1 | Active server metadata enumeration; bounded NSE script | Existing template fixes port 3306 and uses `{{host}}`; canonical should be target and selected port. Requires version bump. | `nmap --script mysql-info -p {port-or-3306} {target}` | Analysis pipeline can create direct not-required task. LLM validator does not expose it, but generic dispatcher/config can. No active tasks; historical rows are unbound. |
| `nuclei_safe` | `nuclei.safe_scan.v1` | Validation | 2 | Active template-based vulnerability validation, bounded to critical/high with rate/timeout/retry controls | Registry exists. Flags match template `nuclei_safe`, but DB endpoint is `{{host}}` while Worker derives scheme/port URL from target, port and service. Strict equality therefore remains partial; create a canonical versioned URL template/renderer or make the builtin execution contract the explicit template authority. | `nuclei -u {derived_url} -severity critical,high -rl 5 -timeout 5 -retries 0 -no-color` with action/identity/parameter-hash verification. | Worker globally requires authorization, so all legacy nuclei tasks fail closed. Direct Decision and LLM paths can still create proposal-like ToolTasks, but they cannot execute. Live DB: 18 historical, one approved/pending legacy task, zero authorizations. |
| `dirb_safe` | `dirb.content_discovery.v1` | Validation | 2 | Active, potentially high-request-volume content enumeration; policy-controlled automatic authorization with optional escalation | Existing template hardcodes `http://{host}` and omits dynamic port/TLS; canonical should be target, port, service and derived URL. Requires a versioned bounded identity, timeout and explicit wordlist/default contract. | `dirb {derived_url}` under Worker process timeout 180; current handler has no action identity or action-specific rate/request ceiling. | Fully legacy. Auto-loop and LLM/decision paths create pending-approval ToolTask; approval makes it executable without ExecutionAuthorization. Live DB: 4 historical tasks. |

Aliases `httpx`, `nuclei`, and `dirb` are input normalization aliases, not separate executable actions. Historical alias rows remain provenance and must not be rewritten.

## Current creation/bypass inventory

| Path | Current behavior | Migration requirement |
|---|---|---|
| `POST /targets` | Direct `nmap_service` ToolTask, no action/auth | Route through deterministic Tier 1 governance without changing target transaction semantics. |
| target retest API | Direct human-requested nmap ToolTask | Preserve human reason; issue fresh bounded authorization, never reuse prior one. |
| `scan_run_dispatcher.py` | Legacy direct nmap creation | Migrate or retire after proving no active deployment depends on it. |
| nmap analysis pipeline | Direct `httpx_basic`, `ssh-enum`, `mysql-info`, or `nuclei_safe` ToolTask | Replace direct writer with proposal/governance service; nuclei already fails closed at Worker. |
| auto-loop `generate_tool_task` | Registry path only for current two actions; other tools remain legacy | Expand `ACTION_BY_TOOL` in small batches and prohibit fallback for each migrated action. |
| `/tools/llm-propose` | Current two actions use registry tier; remaining tools use caller risk/legacy approval | For each migrated action, ignore caller risk for authorization and reject unknown action/tool combinations. |
| manual Decision Engine | Direct ToolTask; vulnerability risk/confidence controls approval | Convert selected action to DecisionProposal; action tier comes only from Registry/policy. |
| approved LLM recommendation generator | Direct pending-approval ToolTask for any accepted recommendation | Convert recommendation approval into proposal evidence, not execution authorization; governance resolves action/tier. |
| Worker poller | Requires authorization globally only for `nuclei_safe` or already-bound tasks | Add each migrated action to fail-closed enforcement atomically with its creation-path migration. |
| Kali Worker `/execute` | Requires identity for nuclei and requests carrying action ID; other tools accept legacy tool-only requests | Add exact action/tool/identity/parameter checks per migration batch; retain legacy only for explicitly unmigrated actions. |

## Migration order

### Batch 0 — close strict-identity gaps in the existing slice

1. Version the symbolic builtin contract for `http_security_headers.collect.v1`.
2. Make every header creation path action-bound or fail closed at Worker/poller.
3. Resolve nuclei endpoint-template identity (`{{host}}` versus derived URL) without redesigning ExecutionAuthorization.
4. Add a static test that every registered action resolves to exactly one enabled template and one Worker identity.

### Batch 1 — bounded collectors

- `dns.metadata_collect.v1`
- `tls.certificate_collect.v1`

Reason: deterministic builtins, bounded network effects, no current historical task pressure and small routing surface.

### Batch 2 — nmap baseline alone

- `nmap.service_fingerprint.v1`

Reason: simple identity but the widest creation surface and three live pending tasks. Preserve deterministic target/retest behavior and do not synthesize authorization for those pending rows.

### Batch 3 — HTTP probe alone

- `httpx.web_probe.v1`

Reason: central auto-loop dependency and URL derivation/template drift require isolated compatibility testing.

### Batch 4 — protocol metadata pair

- `ssh.algorithms_enum.v1`
- `mysql.server_info.v1`

Reason: same bounded nmap-script pattern and same dynamic-port template correction.

### Batch 5 — directory validation alone

- `dirb.content_discovery.v1`

Reason: highest remaining request-volume and governance uncertainty. Define bounded wordlist, request/timeout ceiling and escalation policy before enabling authorization-first execution.

No Tier 3 batch is proposed. A future Tier 3 action requires evidence of an actual registered capability and explicit human-authorization semantics.

## Tests required for every batch

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

## Human decision gate

- Reason: strict Phase 3 equality exposes partial identity gaps in both currently registered actions and multiple executable legacy paths.
- Recommendation: approve Batch 0 first, then approve one migration batch at a time in the order above.
- Alternative: migrate nmap first; rejected as initial order because it has the broadest creation surface and live pending tasks.
- Impact: migrated tools become fail-closed without authorization; historical pending work may remain visible but non-executable.
- Risk: deploying Registry rows before all creation and Worker paths are switched can cause either bypass or unintended execution stalls.
- Requested decision: approve, revise, or reject Batch 0. No implementation begins from this matrix alone.

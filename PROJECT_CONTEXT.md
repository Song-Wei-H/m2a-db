# M2A Pentest DB - Project Context

This file is the authoritative project context for the repository. If README
content conflicts with this document, prefer this document.

## System Positioning

M2A is a governed autonomous security assessment orchestrator. It coordinates
allowlisted tools through `ToolTask` records, analyzes evidence, records
decisions, accumulates learning data, and exports reports.

It is not an unrestricted attack agent, credential attack framework, phishing
delivery system, payload delivery platform, or arbitrary shell execution
system.

## Current Runtime Architecture

### Governed remote evidence collectors (2026-08-14)

M2A and Kali Worker independently allowlist `tls_certificate`,
`http_security_headers`, and `dns_metadata`. `GET /workers/preflight` must return
`READY` before use. Target reachability is governed by deployment NDR and
microsegmentation rather than a Worker CIDR list. Tool allowlisting, fixed
handlers, timeouts and M2A approval gates remain enforced.

```text
Target
-> ScanRun trace
-> initial ToolTask
-> task_poller
-> governed remote/local tool execution
-> ToolResult
-> parser
-> normalized_results
-> evidence_confidence
-> learning_feedback
-> Risk Engine v3
-> DecisionScore
-> auto_loop
-> next governed ToolTask or stop
-> Report Generator
-> Report Export
```

## Source of Truth

`tool_tasks` is the current execution queue and source of truth for worker
execution.

`scan_runs` is retained as an initial scan trace and backward-compatible
container. `POST /targets` creates both a `scan_runs` row and an initial
`nmap_service` `ToolTask`, but workers execute from `tool_tasks`, not directly
from `scan_runs`.

## Completed

- Target creation creates a target, scan run trace, and initial `nmap_service`
  ToolTask.
- ToolTask lifecycle states are centralized in `app/tool_task_constants.py` and
  validated by `app/tool_task_state.py`.
- Worker polling claims only pending tasks whose approval status is
  `not_required` or `approved`.
- Eight actions use the Registry-derived authorization-first path:
  `http_security_headers.collect.v1`, `nuclei.safe_scan.v1`,
  `dns.metadata_collect.v1`, `tls.certificate_collect.v1`,
  `nmap.service_fingerprint.v1`, `httpx.web_probe.v1`,
  `ssh.algorithms_enum.v1`, and `mysql.server_info.v1`.
- Their ExecutionAuthorization binds target, canonical parameters and hash,
  execution identity, template version, scope, expiry, and one execution.
  Claim atomically consumes that execution; caller/LLM risk cannot override
  the Registry tier. Historical approvals are not converted into grants.
- `dirb_safe` remains an explicitly legacy, unmigrated ninth allowlisted tool.
  It is not part of the eight-action authorization-first coverage.
- Tool execution remains constrained by tool policy, command templates, scope
  validation, approval gates, and `shell=False` local execution.
- Remote worker `command` values are stored only as audit data and are not
  executed locally.
- Structured parsers, evidence normalization, evidence confidence, MITRE
  mapping, and learning feedback are implemented.
- Risk Engine v3 is a deterministic risk engine with learning-informed
  adjustment. It considers CVSS, EPSS, KEV, runtime signals, evidence quality,
  and learning feedback. It is not an ML model.
- Auto multi-round execution supports max round checks, duplicate prevention,
  HTTP follow-up routing, approval gates, final stop decisions, and target
  completion.
- Report Generator returns target summary, ports, tool results, normalized
  results, evidence confidence, decisions, risk ranking, MITRE mapping,
  learning summaries, round value summary, matched CVEs, and remediation.
- Report Export supports JSON, HTML, PDF, latest report files, CLI export, and
  non-breaking API export. Export responses include artifact size, SHA-256,
  and target-scoped download URLs. Latest HTML lookup is target-isolated.
- Dashboard and operational endpoints are implemented through the targets API
  router.
- Learning framework, offline knowledge prior, adaptive ranking metadata,
  training dataset pipeline, round labeling, and offline model training
  framework exist as advisory/offline components.
- The optional advisory LLM decision runner builds a minimal local context from
  the current decision evidence and bounded prior advisory outcomes. The model
  receives only that serialized context, never direct database or filesystem
  access, and its response cannot bypass validation or approval gates.

## Current API Surface

Enabled routers in `app/main.py`:

- `app.api.targets`
- `app.api.open_ports`
- `app.routers.decisions`
- `app.routers.llm_tools`
- `app.routers.approval`

Key routes:

- `POST /targets`
- `GET /targets/{target_id}/open-ports`
- `GET /targets/{target_id}/report`
- `GET /targets/{target_id}/report/export`
- `GET /targets/{target_id}/report/download`
- `GET /targets/{target_id}/report/latest`
- `GET /targets/{target_id}/summary`
- `GET /targets/{target_id}/tool-results`
- `GET /targets/{target_id}/decisions`
- `GET /targets/{target_id}/learning-feedback`
- `GET /targets/{target_id}/run-status`
- `GET /dashboard/overview`
- `POST /decisions/run/{target_id}`
- `POST /tools/llm-propose`
- `GET /approvals/pending`
- `POST /approvals/{task_id}/approve`
- `POST /approvals/{task_id}/reject`

ExecutionAuthorization has no public grant-creation endpoint. It is an internal
server-side governance artifact derived from a proposal, Registry contract,
policy, and any required approval; clients and LLMs cannot mint it directly.

## Remaining Work

- Decide a separately governed Batch 5 contract for `dirb_safe` before counting
  it as authorization-first; define its bounded wordlist, request/rate ceiling,
  timeout, canonical URL, and exact execution identity.
- Add authenticated Worker callers or signed grants; current execution identity
  and parameter-hash binding is a consistency control, not cryptographic caller
  authentication.
- Add resolved-destination pinning where deployment NDR/microsegmentation is
  not the authority for target reachability.
- Add API authentication/RBAC before treating approval actor fields as trusted
  production identities.
- Collect enough real historical `round_learning_labels` for reliable offline
  model experiments.
- Validate dataset quality and label distribution on real assessment runs.
- Add optional external dependencies for richer HTML/PDF rendering if needed.
- Add production deployment guidance for report retention and cleanup.
- If runtime model-assisted ranking is desired, add it as a new
  `ToolRankingStrategy` only. Do not modify Decision Engine, Governance, or
  ToolTask lifecycle for that integration.

## Safety Boundary

Do not add:

- brute force or credential stuffing
- password spraying
- phishing delivery
- payload delivery
- EDR or antivirus bypass
- arbitrary shell execution
- arbitrary argv execution
- unrestricted subprocess execution

All new runtime execution must preserve tool registry validation, command
template rendering, scope validation, approval gates, and ToolTask lifecycle
rules.

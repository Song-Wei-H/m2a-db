# Phase 3 Batch 3 Completion

Date: 2026-08-20  
Baseline: `a486c196bbdfbceb80d5abb37577d965b7c0a077`  
Scope: `httpx.web_probe.v1` only

## Canonical contract and redirect boundary

`httpx.web_probe.v1` is Discovery Tier 1 with template
`httpx_web_probe_v2`. Canonical parameters bind target/host, deterministic
scheme, port, root path, canonical URL, probing behavior, exact flags, timeout
and retry semantics. Worker argv is exactly:

```text
httpx -u {canonical_url} -json -title -tech-detect -status-code
```

Redirect following was removed. The action authorizes one root URL and zero
redirects, so cross-host, cross-scheme and cross-port redirect scope expansion
cannot occur. Target, scheme, port, URL, path, flags, template or execution
identity drift fails closed.

## Post-httpx decision boundary

All HTTPx creation paths use the shared migrated-action writer or governed task
generator. HTTPx evidence may influence the existing decision/Auto Loop, but
already migrated downstream actions (Header, Nuclei, DNS, TLS and nmap) still
require proposal -> Registry -> authorization before ToolTask creation. Dirb
remains legacy and was not migrated.

## Validation

- Migration 031 applied twice to PostgreSQL 16: PASS.
- Registry/action/template exact no-redirect argv: PASS.
- Full backend suite: `366 passed`.
- Real PostgreSQL HTTPx concurrent claims: `[True, False]`, consumed count 1.
- Frontend build: PASS.
- No real Target or HTTPx execution occurred.

Remaining risk: HTTPx default retry/probe behavior can vary by installed
version; version pinning remains a reproducibility follow-up. Batch 4 was not
started and requires separate human authorization.

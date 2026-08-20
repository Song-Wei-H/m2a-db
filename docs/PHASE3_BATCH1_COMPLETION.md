# Phase 3 Batch 1 Completion

Date: 2026-08-20  
Baseline: `1c36e4e6c0b97def6e1ca6b4308140bf93064acd`  
Scope: `dns.metadata_collect.v1`, `tls.certificate_collect.v1` only

## Authoritative tiers and contracts

| Action | Phase | Tier | Template | Canonical execution contract |
|---|---|---:|---|---|
| `dns.metadata_collect.v1` | Discovery | 0 | `dns_metadata_v2` | System `getaddrinfo` A/AAAA, PTR only for IP targets, canonical-name lookup, zero application retry, outer Worker request timeout ceiling |
| `tls.certificate_collect.v1` | Discovery | 1 | `tls_certificate_v2` | One TCP/TLS client handshake, authorized host/port/SNI, timeout 10 seconds, TLS verification disabled for evidence collection, certificate SHA-256 |

DNS remains Tier 0 because the implementation is bounded metadata acquisition,
not validation or mutation. Its resolver timeout is honestly represented as the
system resolver under the outer Worker request ceiling; no per-query timeout is
claimed. TLS remains Tier 1 because it performs a bounded network handshake.
Caller/LLM risk fields are telemetry only and cannot change these tiers.

## Legacy closure and boundary behavior

Both tools are now protected by the same canonical writer, poller and remote
Worker gates as Batch 0. A legacy DNS/TLS ToolTask request is adapted through
DecisionProposal -> Registry -> automatic ExecutionAuthorization. A tool-only
Worker request is rejected. Target/domain/host/port/SNI/parameters, template,
execution identity, expiry and replay mismatches fail closed.

## Validation evidence

- Migration 029 applied twice to PostgreSQL 16 with `ON_ERROR_STOP`: PASS.
- Registry -> ValidationAction -> enabled v2 CommandTemplate mapping: PASS.
- Backend full suite: `352 passed`.
- Real PostgreSQL TLS concurrent claims: `[True, False]`, `consumed_count=1`.
- Frontend `tsc -b && vite build`: PASS.
- No real Target or scanner execution was performed.
- Historical ToolTasks/authorizations were not backfilled.

## Remaining risks and Batch 2 readiness

- DNS resolution inherits operating-system resolver behavior. The outer request
  timeout bounds GADE's wait, but it is not evidence of a portable per-query DNS
  timeout. Boundary identity remains deterministic for target and query behavior.
- API/poller, migration and Kali Worker must be deployed together; mixed versions
  intentionally fail closed.
- Batch 2 was not started and requires separate human authorization.

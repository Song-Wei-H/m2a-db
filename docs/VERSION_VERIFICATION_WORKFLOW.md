# Version verification workflow

## Purpose

M2A treats a `cpe_product_only` CVE association as **Version Unverified**. It
is external intelligence, not target applicability. The analysis pipeline now
applies the deterministic confidence-driven policy, selects at most the governed
Top-N candidates, and may create an approved safe-validation task when the
confidence and priority gates pass. It no longer stops solely because the version
is unknown. Product-only correlation still never confirms a vulnerability.

## Evidence contract

`httpx_basic` may preserve a version only when the Kali worker's structured
result contains an explicit `version`, `webserver_version`, or
`web_server_version` field.  M2A records:

```json
{
  "product": "nginx",
  "version": "1.26.1",
  "version_source": "httpx_explicit_field",
  "version_status": "observed"
}
```

Titles, technology names, and guessed server banners are not version evidence.
Every record must retain its `tool_result` evidence reference and raw output.

## Proposed worker capability: `http_version_verify`

This is a contract, not an enabled tool.  It must remain
`REQUESTED_NOT_DEPLOYED` until the Kali Worker source implements it, advertises
it in `/health`, and its parser and allowlist tests pass.

Allowed operation: a single read-only HTTP(S) request to the in-scope service,
using only passive response metadata already returned by the endpoint.  It may
not authenticate, enumerate paths, send mutation methods, upload data, follow
untrusted redirects, or retry automatically.

Required structured result fields:

```json
{
  "success": true,
  "version_observed": true,
  "product": "string",
  "version": "string",
  "version_source": "response_header|structured_metadata",
  "url": "https://in-scope-host:port/",
  "status_code": 200,
  "raw_output": "traceable worker output"
}
```

If no explicit version exists, return `version_observed: false`; do not guess.
M2A must then retain `VERSION_VERIFICATION_REQUIRED` and ask for an approved
inventory or administrative version source.

## Reassessment and decision

Only after product and exact version are evidenced may M2A reassess NVD affected
version ranges.  A matching range can produce a `CVE Candidate` for governed
low-impact verification; it is still not a confirmed finding.  High-impact
verification remains `PENDING_HUMAN_DECISION` with reason, recommendation,
evidence, alternatives, impact, risk, and requested decision.

## Worker failure

`nuclei_safe` timeout is `Tool Failure`, never `No Finding`.  M2A issues a stop
decision with automatic retry disabled.  A retry requires successful
`GET /workers/preflight` and a separate human approval for a bounded retry.

# Confidence-Driven CVE Validation

M2A keeps three authority boundaries separate:

1. A product correlation is a `PRODUCT_CANDIDATE` / `VERSION_UNRESOLVED` claim.
2. Product identity confidence is independent from version status.
3. Version is filtering evidence, not a validation prerequisite.
4. Validation priority ranks safe validation value; only target evidence can produce `VALIDATED`.

## Deterministic policy

The single policy source is `worker/cve_validation_policy.py` (`confidence-driven-cve-v2`).
Product identity uses existing evidence classes without a second fingerprint framework:
`service_only` 0.10, `technology_only` 0.45, `product_only` 0.75,
`cpe_product_only` 0.92, `product_version` 0.85, and exact CPE/version 0.98.
An explicit evidence-derived `product_identity_confidence` takes precedence.

```text
version_status = KNOWN | UNKNOWN | INFERRED | CONFLICTING
```

CVSS, EPSS, and KEV are deliberately absent from this formula. Validation priority is:

```text
0.45 * product_identity_confidence
+ 0.20 * normalized_cvss
+ 0.15 * epss
+ 0.15 * kev
+ 0.05 * evidence_confidence
```

Product identity at least 0.70, product relevance, and a compatible registered tool
enter the `VERIFY` candidate pool even when version status is `UNKNOWN`. Validation
priority orders that pool but is not vulnerability confidence. At most
`MAX_CVE_VALIDATIONS_PER_ROUND` (default 3) survive; the remainder become `DEFERRED`.

## Governed routing and risk

Selected candidates use the existing `nuclei_safe` action. The existing ToolRegistry,
GADE proposal/authorization, Approval, ToolTask, Worker, ToolResult, and Evidence path
remains mandatory. A missing/disabled compatible tool returns `DEFER` and creates no
arbitrary command or capability request.

Product-only intelligence affects validation priority, not Risk Engine v3 target CVSS,
EPSS, or KEV inputs. Those inputs remain restricted to high-confidence exact-version
matches, so a product-only CVSS 9.8 candidate cannot independently make a target critical.

## Reporting and experiment trace

Reports render the top five candidates and an additional-candidate count. Candidate rows
include product identity, version status, priority/rank, selection, state, decision,
and claim-scoped evidence references.
`cve_validation_trace` supplies the required target/scan/decision/task/result identifiers,
CVE intelligence, decisions, outcomes, and evidence confidence for offline experiments.

## State semantics

`PRODUCT_CANDIDATE`, `VERSION_UNRESOLVED`, `VERSION_APPLICABLE`, `VALIDATION_PENDING`,
`VALIDATED`, `NOT_VALIDATED`, `NOT_APPLICABLE`, and `DEFERRED` are data/decision values in existing JSON fields;
no database migration is required. Candidate, applicable, and validated remain distinct.

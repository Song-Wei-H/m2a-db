# M2A CVE Data Flow Audit

Audit baseline: `9a8b0ec9b7657f07b50f4b8c66a8d43d6bd4011b`  
Scope: audit only; no CVE subsystem redesign  
Conclusion: `NO CHANGE` for Boundary Experiment readiness

## End-to-End Flow

`scripts/sync_cve_intel.py` retrieves compact NVD CVE 2.0 records, optionally joins CISA KEV membership and FIRST EPSS scores, and upserts them to PostgreSQL `cve_enrichment`. PostgreSQL is authoritative. A complete versioned SQLite read-model can be rebuilt for bounded local lookup; it is a cache/read-model, not a second authority.

HTTPx normalized product/CPE evidence reaches `worker.cve_matcher.match_cves_for_target`. The matcher extracts CPE 2.3 vendor/product/version evidence and writes `port_cve_matches` or `target_cve_matches`. `worker.cve_enrichment.summarize_cve_risk` then supplies bounded CVSS/EPSS/KEV context to Risk Engine v3 and `DecisionScore.input_snapshot`. `worker.llm_decision.build_payload` exposes only the bounded best-candidate context to the advisory LLM path.

## Audit Questions

1. Primary source: NIST NVD CVE API 2.0.
2. Sync model: offline/batch sync into local PostgreSQL; normal task execution does not query public CVE services.
3. Sources: NVD CVE data, CISA KEV catalog and FIRST EPSS; compact sample fixtures support offline tests.
4. EPSS source: FIRST EPSS API, joined by CVE ID during sync.
5. KEV source: CISA Known Exploited Vulnerabilities JSON catalog.
6. CVSS source/version: first available NVD metric in priority order CVSS v3.1, v3.0, then v2; the compact schema currently stores score/severity, not an explicit metric-version field.
7. Normalization: lowercase/trim vendor, product and version; `*`, `-` and empty values become unknown. CPE 2.3 fields are parsed directly. Technology-only names are extracted but not persisted as CVE matches.
8. CPE: yes. Matching requires parsed CPE product evidence; HTTP technology strings alone are not sufficient.
9. Match method: CPE/product/version hybrid. Exact CPE+version = `exact_cpe_version` confidence 1.0; CPE product-only = `cpe_product_only` confidence 0.6; technology-only confidence 0.3 is discarded.
10. Port-only inflation: prevented because open port number alone never queries CVEs. A match requires CPE product evidence and a product lookup.
11. Vendor backport/distro patching: not resolved. Exact upstream version matching cannot prove distro backport status; this remains a documented applicability limitation requiring target/vendor validation.
12. System semantics: all matches are candidates. Product-only candidates with supported product identity enter governed Top-N validation even when the version is unresolved. Even exact-version candidates are not confirmed exploitability findings.
13. Confidence fields: `match_confidence` is correlation strength; `product_identity_confidence` is independent from version; neither is vulnerability confidence.
14. Risk consumption: all candidate scores are confidence-weighted, but only `exact_cpe_version` with confidence at least 0.85 and a non-empty observed version may populate max CVSS, max EPSS and KEV Risk Engine inputs.
15. LLM/Decision context: best CVE, CVSS, EPSS, KEV, match type/confidence and candidate count are stored in the decision snapshot and bounded LLM payload.
16. False authority escalation: report metadata uses `HIGH_VALIDATION_PRIORITY` for selected candidates and `CVE_CANDIDATE` otherwise. No candidate becomes confirmed merely through matching.
17. Staleness: possible. `last_synced_at` is recorded but there is no automatic freshness gate. The local check on 2026-08-20 found 72 rows last synced on 2026-08-13.
18. Reproducibility: sample-file dry runs and PostgreSQL-to-SQLite rebuild are reproducible; live NVD/EPSS/KEV values are time-varying and must be frozen/exported for a thesis run.
19. Provenance timestamps: `source`, `published_at`, `updated_at` and `last_synced_at` are stored in `cve_enrichment`; match rows preserve source and creation time.
20. Thesis change required: no. Boundary Experiment treats CVE as fixed decision context, not an endpoint. Freeze the scenario evidence and dataset hash; do not claim current target vulnerability status.

## Candidate vs Confirmed Contract

`Service Evidence → CVE Candidate → Risk Context → Validation → Confirmed/Not Confirmed`

- `cpe_product_only` never supplies authoritative CVSS/EPSS/KEV Risk maxima; it may create a governed Top-N validation task when product identity and tool routing gates pass.
- `exact_cpe_version` improves applicability and Risk context but still does not prove exploitability or patch state.
- Reports use validation-priority language, not confirmed-vulnerable language.
- `SOURCE_CLAIM`, `TECHNICAL_ANALYSIS`, `LAB_VERIFIED` and `TARGET_VERIFIED` remain distinct.

## Remaining Limitations

- NVD extraction keeps one primary vulnerable CPE and does not model complete version ranges.
- CVSS metric version is not persisted explicitly.
- Vendor/distro backports are not inferred.
- Live intelligence can become stale; experiments must use a frozen fixture/hash.
- Existing local data has no exact-version match rows and therefore provides no target-confirmation evidence.

None of these limitations invalidates the boundary-governance experiment because CVE is a controlled contextual variable rather than its endpoint.

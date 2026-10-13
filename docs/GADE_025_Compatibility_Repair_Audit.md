# GADE Migration 025 compatibility repair audit

Status: repair applied; host PostgreSQL validation pending. Pre-experiment baseline remains **NOT READY** until the host orchestrator passes its migration, application, regression, build, and Git gates.

## Root cause

Migration 018 creates `normalized_results.normalized_output JSONB`; it does not create `normalized_data`. The original Migration 025 unconditionally referenced `normalized_data`, so a clean 018 schema failed at 025 with PostgreSQL error `column "normalized_data" does not exist`.

The scoped repair checks `information_schema.columns` inside a PL/pgSQL branch and uses dynamic SQL only when the legacy column exists. The original predicates and assignment are preserved: copy non-NULL `normalized_data` into NULL `normalized_output`; leave an existing output unchanged; retain the source column. When the old column is absent there is no source value to backfill, and the 025 schema additions, foreign key, and index still run.

## Hashes and original failure

- 025 before: `9797c8c0394fcc7504da4b65136028c72b458d8b2ed64129fa748b6377b88536`
- 025 after: `d088b88e230d20c7d5ab63a7a3039bb54c6e946d20b6ef36b2481c870d7f6bd3`
- Original baseline HEAD: `33e9cf64567d99e4f1baa4f8103249ce8fb2e704`
- Failed scratch container: `ee18445a9552302540099966c8f2b7598222526041837cb68291adc4f7bca898`
- Original log: `%LOCALAPPDATA%\M2A\MigrationSmoke\migrations-20261013-125722-b03532f6.log`
- Original log SHA-256: `6a969d1e01f4afe012aa9adb4931f63b9b30a7715e43cbd08a703ed9eaab9e92`

The original log shows 001–024 PASS and 025 FAIL; 026–036 did not run. It remains historical evidence and is never rewritten as a patched run.

## Migration 037 live-evidence gate

The operator's read-only PostgreSQL verification was read from the unique local-only JSON artifact `reports/local-only/host-verification/f29fe50313b9/20261013T070538679Z-fa0fb1dcdd87432ba08d319cb62e1af3/verification.json`. Container identity matched the recorded `legacy025` container ID, name, `postgres:16` image, run/profile labels, loopback port 25957, database/user, and named volume. Both identity and query status were PASS, the query exit code was 0, and stderr was empty. Raw SQL output reported:

```text
TABLE|evidence_confidence|NULL
TABLE|llm_recommendations|NULL
```

Migration `037_llm_evidence_tables.sql` adds only those two absent ORM-mapped tables. Its schema follows `app/models.py`; it adds no foreign keys or secondary indexes. The migration requires the validated Migration 036 coverage column, constraint, and index, and fails closed if either target relation already exists. Live PostgreSQL execution is pending a new isolated Host Validation Run; the old `f29fe50313b9` run and its evidence are not modified or resumed.

The exact source change is captured in [GADE_025_normalized_results_applied.diff](GADE_025_normalized_results_applied.diff). No other numbered migration was changed for this repair.

## Host validation

`scripts/Invoke-GadePreExpHostValidation.ps1` runs the missing-column fresh scenario, the legacy-column backfill fixture, and the separate 033–036 legacy compatibility fixture against new run-scoped PostgreSQL 16 containers and volumes. The host run checks the complete container ID, image, label, port binding, database identity, empty schema, migration hashes, 033–036 constraints, and SQLAlchemy mapped columns.

The orchestrator saves per-stage output, migration logs, schema-only dumps, manifests, and SHA-256 values under `reports/experiments/gade-preexp-host-validation/<run-id>/`. It requires one explicit confirmation after displaying all resources it will create. It does not inspect, stop, rename, reset, or delete the earlier failed container or volume.

Codex-side static checks passed before host execution. PostgreSQL execution and application tests must be reported from the host logs; the repair is not marked runtime-verified until then.

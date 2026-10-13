# GADE PostgreSQL baseline host validation

Run the orchestrator from ordinary Windows PowerShell with Docker Engine available. Codex must not invoke Docker. The orchestrator uses three new run-scoped containers and named volumes on `127.0.0.1` ports 25436–25999, with database names limited to `gade_<run-id>_<profile>`. It never targets `m2a_pentest`, port 15432, Compose resources, or the earlier `m2a-migration-smoke` container/volume.

## Read-only preflight

```powershell
Set-Location C:\Users\p2166\m2a-db
.\scripts\Invoke-GadePreExpHostValidation.ps1 -PreflightOnly
```

The preflight prints the selected run ID, all container/volume names, ports, database identities, image, output paths, source hashes, current Git changes, and the required one-time confirmation phrase. It does not create files, containers, databases, or volumes. For a single-command run, omit `-PreflightOnly`; after reviewing the printed plan, enter the one confirmation phrase. The script continues through all PostgreSQL baseline stages automatically.

## Start or resume

```powershell
.\scripts\Invoke-GadePreExpHostValidation.ps1 -RunId <printed-12-hex-run-id>
```

After reviewing the full resource list, enter the exact phrase printed by the script once. It then proceeds through each passing stage automatically and saves a checkpoint after every stage. On interruption, resume with:

```powershell
.\scripts\Invoke-GadePreExpHostValidation.ps1 -Resume -RunId <same-12-hex-run-id>
```

The script refuses to rerun a failed or interrupted database-writing stage in the same database. It preserves that run's logs and resources; a retry after a source change uses a new run ID and new containers/volumes.

## Stage order and gates

1. Migration 025 with controlled `normalized_data` source rows; assert copy, preserve, NULL, and source-retention behavior.
2. Fresh schema migrations 001–037 with no `normalized_data` column.
3. A distinct historical-row fixture migrated through 033–037.
4. Export schema-only evidence for all three databases; assert 033–036 constraints, Foreign Keys, indexes, defaults, trace and coverage fields, Migration 037 columns/defaults/PK-only shape, and complete ORM column compatibility.
5. Run the isolated backend application smoke, including SQLAlchemy INSERT/SELECT and JSONB round trips for both Migration 037 models, then verify created rows are cleaned up.
6. Run the complete backend regression. The PostgreSQL trace integration test is directed to a transaction-local schema inside the fresh scratch database.
7. Run the frontend production build.
8. Compare historical experiment hashes, check Git scope and whitespace, stage only allowlisted source files, create a new PostgreSQL baseline commit, and create local annotated tag `gade-preexp-v1` if it does not already exist.

This run ends at the PostgreSQL baseline gate. It does not run the seven-level Worker, A/B/C, LLM, or thesis work.

Artifacts and checkpoints are stored beneath `reports/experiments/gade-preexp-host-validation/<run-id>/`. Failure leaves new resources intact for diagnosis. The original failed 025 container, database, volume, and log are never touched.

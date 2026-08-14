# M2A Troubleshooting

## UI action returns `Not Found`

Cause: the UI is connected to an older API process that does not expose the
route used by the current frontend. A listening port alone does not prove API
compatibility.

Use the governed launcher:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-ui.ps1
```

The launcher resolves the repository from its own script path, probes only the
bounded API ports 8000-8005, reads `/openapi.json`, and accepts an API only when
both `/workers/preflight` and `/automation/targets/{target_id}/start` exist. It
then chooses the first free UI port from 5173-5178 and configures the Vite proxy.

If no compatible API is found, start the API first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-api.ps1 -NoReload
```

Do not fix this by blindly killing the process on port 8000/8001. Resolve its
PID and command line first. Multiple stale API/UI instances should be stopped
only after their identity is verified.
# Target fails immediately with `outside allowed scope`

If a newly selected target completes in round 1 with no findings, inspect the failed ToolTask before assuming the host has no services. A message such as `Target ... is outside allowed scope` means the M2A process is still enforcing a local CIDR allowlist.

For deployments where authorization is enforced by NDR and microsegmentation, configure:

```env
ENFORCE_TARGET_SCOPE=false
ALLOWED_SCOPES=
```

Restart every active M2A API/worker process after changing `.env`. M2A continues to validate IP/hostname syntax and enforce the tool allowlist, fixed handlers, approval policy, and non-shell execution. Set `ENFORCE_TARGET_SCOPE=true` to restore explicit CIDR/hostname allowlisting.

Do not run several API instances against the same database. `scripts/start-api.ps1` now reuses an existing compatible singleton by default, and `scripts/start-ui.ps1` refuses to bind when it detects multiple compatible APIs. This prevents a stale process with old environment settings from executing newly created ToolTasks. Use `-AllowAdditionalInstance` only for an intentionally isolated database/environment.

# SQLite CVE index cannot be replaced on Windows

Symptom: `PermissionError [WinError 32]` while publishing `data/cve_index.sqlite3`.

The publisher must explicitly close the SQLite connection before `os.replace`; transaction context management alone does not close the Windows file handle. The implemented publisher uses `contextlib.closing`, writes a complete temporary database, commits and closes it, then atomically replaces the active index. PostgreSQL fallback remains available if publication fails.

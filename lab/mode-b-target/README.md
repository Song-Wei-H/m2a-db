# Mode B lightweight lab target

This deterministic HTTP fixture exists only for the authorized M2A lab. It
exposes a fake `.git/config`, a directory listing and deliberately missing HTTP
security headers. It contains no credential, payload, shell or production data.

Runtime constraints: non-root UID 101, read-only filesystem, all Linux
capabilities dropped, no-new-privileges, 128 MiB memory, 0.25 CPU and 64 PIDs.
The only published endpoint is the company-laptop
address `10.56.66.119:18080`; the host firewall must restrict it to the approved
Kali source `10.56.64.121`.

Start and validate:

```powershell
docker compose -f compose.mode-b-target.yml up -d
docker compose -f compose.mode-b-target.yml ps
Invoke-WebRequest http://10.56.66.119:18080/healthz -UseBasicParsing
```

Stop without deleting M2A data:

```powershell
docker compose -f compose.mode-b-target.yml stop
```

## GADE L3 controlled execution emulation

The isolated L2 sidecar also exposes `POST /lab/execute`. It accepts only an
empty JSON object and a valid existing L2 bearer session. The handler launches
the fixed `l3_execution_task.py` using an argv list with `shell=False`; callers
cannot provide code, a command, or a file path. The child performs a deterministic
calculation and writes a run/case/request-bound marker under the sidecar's
ephemeral `/tmp/gade-l3` directory. This is a controlled T1059.006 Python
execution emulation, not validation of an arbitrary-code-execution vulnerability.

Target-side evidence can be queried with `GET /lab/admin/l3-evidence?run_id=...&case_id=...&request_id=...`
and the local reset key in the `X-Lab-Reset-Key` header. The endpoint returns only
the requested execution record, matching audit events, and marker metadata. A
successful `POST /lab/admin/reset` clears the marker, execution records, and
sessions. The target audit log contains UTC request, process-start, completion,
exit-status, and SHA-256 fields; it never logs the account password, reset key,
or session token.

From Windows PowerShell 5.1, the scoped host runner builds and recreates only the
existing `mode-b-l2-auth` sidecar, verifies that the Nginx target container ID
does not change, then runs L3 reset/session/execute/marker/expiry checks and L1/L2
target regressions. It requires the exact confirmation `DEPLOY-GADE-L3-TARGET`.
The Docker build context is restricted by `.dockerignore` to the two runtime
Python files, so local credentials and validation scripts are not sent to the
Docker builder.

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File 'C:\Users\p2166\m2a-db\lab\mode-b-target\Invoke-GadeL3TargetHost.ps1'
```

Target startup is `LAB_READY`, not `LAB_VERIFIED`. Scanner output must remain
separate from a confirmed target finding until governed evidence is preserved.

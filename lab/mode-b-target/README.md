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

Target startup is `LAB_READY`, not `LAB_VERIFIED`. Scanner output must remain
separate from a confirmed target finding until governed evidence is preserved.

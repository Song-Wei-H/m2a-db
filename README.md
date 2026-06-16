# M2A Pentest Orchestration Platform

FastAPI + PostgreSQL + Dispatcher + Kali Worker based governed penetration testing orchestration platform.

This project implements a deterministic-first, auditable, approval-driven execution loop for controlled security assessment workflows.

Authoritative project context:

```text
PROJECT_CONTEXT.md
```

If README and PROJECT_CONTEXT.md conflict, follow PROJECT_CONTEXT.md.

---

## Project Positioning

The platform is designed to coordinate approved security assessment tools through strict governance controls.

The platform is NOT:

* an autonomous exploitation framework
* an unrestricted shell execution system
* a self-directed attack agent
* a credential brute-force platform

---

## Current MVP Execution Loop

```text
Target
↓
ToolTask
↓
Worker
↓
ToolResult
↓
Analysis Pipeline
↓
Decision
↓
Task Generator
↓
ToolTask
```

Goal:

Create a complete governed execution loop from target intake to controlled tool execution, result persistence, analysis, decision, and next-task generation.

---

## Core Architecture

```text
Target
↓
Dispatcher
↓
Policy Validation
↓
ToolRegistry Validation
↓
ToolTask
↓
Worker
↓
Approval Validation
↓
CommandTemplate Rendering
↓
subprocess(shell=False)
↓
Parser
↓
ToolResult
↓
Analysis Pipeline
    ├─ Evidence Normalizer
    ├─ MITRE Mapper
    ├─ Confidence Engine
    └─ Decision Engine
↓
Task Generator
↓
ToolTask
```

---

## Governance Boundaries

Must preserve:

* ToolRegistry validation
* Tool Policy validation
* Scope validation
* LLM schema validation
* CommandTemplate validation
* Human approval workflow
* async transaction boundaries
* worker lifecycle
* subprocess(shell=False) boundary
* timeout handling
* ToolResult persistence

LLM MAY:

* recommend tools
* recommend actions
* produce structured JSON decisions

LLM MUST NOT:

* execute subprocess
* generate raw shell commands
* generate arbitrary argv
* bypass ToolRegistry
* bypass Tool Policy
* bypass Scope validation
* bypass CommandTemplate
* bypass approval workflow
* write ToolResult directly

---

## Allowed Tools

Allowed:

* nmap_service
* httpx_basic
* nuclei_safe
* dirb_safe
* ssh-enum
* mysql-info

Forbidden:

* hydra
* password spraying
* credential stuffing
* unrestricted brute force
* arbitrary command execution
* raw shell execution
* raw argv execution

---

## Scope Restrictions

Allowed scopes:

* 192.0.2.0/24
* 203.0.113.0/24

Configured through:

```env
ALLOWED_SCOPES=192.0.2.0/24,203.0.113.0/24
```

---

## Environment Requirements

* Python 3.11+
* PostgreSQL
* Docker / docker-compose
* Kali Worker host
* Windows PowerShell for local development scripts

Default PostgreSQL port:

```text
15432
```

Default Kali Worker:

```text
http://192.0.2.10:9001
```

Kali Worker may not have internet access. Required tools or packages should be transferred from Windows to Kali manually when needed.

---

## Long-Running Processes

The following processes are designed to run persistently. Do not start duplicate instances during testing.

| Process            |          Default Port | Description                          |
| ------------------ | --------------------: | ------------------------------------ |
| FastAPI / uvicorn  | 8000 or fallback 8001 | API service                          |
| scan_run_dispatcher.py |              none | Creates initial nmap ToolTask records |
| Kali Worker        |                  9001 | Worker host for tool execution       |
| worker.task_poller |                  none | Polls pending ToolTask records       |

Duplicate uvicorn instances may cause:

```text
[WinError 10013]
```

because the port is already in use.

---

## Configuration

Create and adjust `.env`:

```env
DATABASE_URL=<postgresql_async_database_url>
KALI_WORKER_BASE_URL=http://192.0.2.10:9001
DISPATCHER_POLL_INTERVAL_SECONDS=10
KALI_WORKER_TIMEOUT_SECONDS=600
DISPATCHER_STALE_RUNNING_MINUTES=30
API_PORT=8000
ALLOWED_SCOPES=192.0.2.0/24,203.0.113.0/24
ALLOWED_LLM_PROFILES=internal
ALLOWED_TOOLS=nmap_service,httpx_basic,nuclei_safe,dirb_safe,ssh-enum,mysql-info
```

Install dependencies:

```powershell
cd c:\Users\p2166\m2a-db
py -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

---

## Database Migrations

For existing databases, apply migration files from `initdb/` in order.

Known migrations:

```text
002_scan_results.sql
003_scan_results_legacy_columns.sql
004_open_ports_unique.sql
005_decision_engine.sql
006_decision_scores_fix.sql
007_tool_results_task_id.sql
008_tool_tasks_reject.sql
```

Restart the API after schema changes.

---

## Start Services

### Terminal 1 — API

Recommended:

```powershell
.\scripts\start-api.ps1
```

Or:

```powershell
.\.venv\Scripts\python scripts\start-api.py
```

Manual fallback:

```powershell
.\.venv\Scripts\python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

### Terminal 2 — Dispatcher

Run only one instance:

```powershell
.\.venv\Scripts\python scan_run_dispatcher.py
```

Legacy `dispatcher.py` has been archived under `_archive/legacy_unused/`.

### Terminal 3 — Worker Task Poller

Windows development host:

```powershell
.\scripts\run-worker.ps1
```

Kali / Linux:

```bash
python3 -m worker.task_poller
```

Single-run mode:

```powershell
.\scripts\run-worker-once.ps1
```

Linux single-run mode:

```bash
chmod +x scripts/run-worker-once.sh
./scripts/run-worker-once.sh
```

---

## API Summary

| Method | Path                              | Description                         |
| ------ | --------------------------------- | ----------------------------------- |
| POST   | `/targets`                        | Create target and initial scan/task |
| GET    | `/targets/{target_id}/open-ports` | List open ports for target          |
| POST   | `/decisions/run/{target_id}`      | Run deterministic decision engine   |
| POST   | `/tools/llm-propose`              | Accept governed LLM tool proposal   |
| GET    | `/approval/pending`               | List pending approvals              |
| POST   | `/approval/{task_id}/approve`     | Approve ToolTask                    |
| POST   | `/approval/{task_id}/reject`      | Reject ToolTask                     |

Exact available routes may vary by current implementation. Use:

```powershell
.\scripts\check-api-routes.ps1
```

---

## Basic Target Test

Windows should use `Invoke-RestMethod`, not `curl`, because PowerShell aliases `curl`.

Create a target:

```powershell
.\scripts\post-target.ps1 -Target "192.0.2.10"
```

Or manually:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/targets" `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"target":"192.0.2.10"}'
```

Query open ports:

```powershell
.\scripts\get-open-ports.ps1 -TargetId 5
```

Or manually:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/targets/5/open-ports" -Method Get
```

Expected fields:

```text
port
protocol
service
product
version
extra_info
ip
scan_run_id
```

---

## Decision Engine Test

Run deterministic decision engine:

```powershell
.\scripts\run-decision.ps1 -TargetId 5
```

Or:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8001/decisions/run/5" -Method Post
```

Expected response fields:

```text
target_id
next_action
next_tool
mitre_phase
mitre_technique
risk_score
confidence
reason
```

Possible `next_action` values:

```text
continue
verify
remediate
stop
```

Possible `next_tool` values:

```text
httpx_basic
nuclei_safe
dirb_safe
mysql-info
ssh-enum
nmap_service
none
```

`continue` or `verify` with a non-`none` tool should create a `tool_tasks` record.

---

## Worker Execution Test

Run decision:

```powershell
.\scripts\run-decision.ps1 -TargetId 1
```

Run worker once:

```powershell
.\scripts\run-worker-once.ps1
```

Check ToolTask:

```sql
SELECT id, target_id, tool_name, status, approval_status
FROM tool_tasks
ORDER BY id DESC
LIMIT 5;
```

Check ToolResult:

```sql
SELECT id, tool_task_id, tool_name, success, LEFT(raw_output, 80)
FROM tool_results
ORDER BY id DESC
LIMIT 5;
```

---

## LLM Tool Proposal Boundary

LLM can only produce structured JSON.

Allowed example:

```json
{
  "tool": "httpx_basic",
  "target": "192.0.2.10",
  "reason": "Probe HTTP service",
  "risk_level": "low",
  "profile": "internal",
  "target_id": 1
}
```

Forbidden fields include:

```text
command
shell
raw_command
argv
subprocess
payload
```

Test governed LLM proposal:

```powershell
.\scripts\propose-llm-tool.ps1 -TargetId 1 -Target "192.0.2.10" -Tool "httpx_basic"
```

Out-of-scope test, expected rejected:

```powershell
$body = @{
  tool="nmap_service"
  target="8.8.8.8"
  reason="test"
  risk_level="low"
  profile="internal"
  target_id=1
} | ConvertTo-Json

Invoke-RestMethod `
  -Uri "http://127.0.0.1:8001/tools/llm-propose" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

---

## CommandTemplate Boundary

Worker must execute only fixed templates.

Examples:

```text
nmap_service  → /usr/bin/nmap -sV -Pn <target>
httpx_basic   → /usr/bin/httpx -title -tech-detect -u <url>
nuclei_safe   → /usr/bin/nuclei -severity low,medium,high,critical -u <url>
dirb_safe     → /usr/bin/dirb <url>
ssh-enum      → controlled SSH enumeration template
mysql-info    → controlled MySQL information template
```

Worker execution must use:

```python
subprocess.run(argv, shell=False, timeout=...)
```

Raw shell commands are not allowed.

---

## Analysis Pipeline

ToolResult enters the analysis pipeline:

```text
ToolResult
↓
normalize_tool_result()
↓
map_to_mitre()
↓
calculate_confidence()
↓
decide_next_action()
↓
generate_tool_task()
↓
ToolTask
```

Implemented components:

```text
worker/evidence_normalizer.py
worker/mitre_mapper.py
worker/confidence_scoring.py
worker/risk_engine_v3.py
worker/analysis_pipeline.py
worker/task_generator.py
```

---

## Current Priority

Current focus is defined in:

```text
PROJECT_CONTEXT.md
```

Current priority:

```text
Worker Execution Audit
```

Audit files:

```text
app/tool_task_dispatcher.py
worker/task_poller.py
worker/command_templates.py
worker/task_generator.py
```

Main audit questions:

1. Can ToolTask reach Worker?
2. Can Worker execute allowlisted templates?
3. Is ToolRegistry enforced?
4. Is Tool Policy enforced?
5. Is Scope validation enforced?
6. Is LLM schema validation enforced?
7. Is CommandTemplate enforced?
8. Is subprocess(shell=False) enforced?
9. Is approval validation enforced before execution?
10. Where is ToolResult written?
11. Can ToolResult re-enter Analysis Pipeline?
12. Can Analysis Pipeline generate the next ToolTask?
13. What is missing before the full governed execution loop works?

---

## Troubleshooting

### `[WinError 10013]` / port 8000 already in use

Check listener:

```powershell
netstat -ano | findstr :8000
```

Kill old uvicorn:

```powershell
taskkill /PID <PID> /F
```

Or start on another port:

```powershell
.\scripts\start-api.ps1 -Port 8001
```

Force 8000 only, fail if occupied:

```powershell
.\scripts\start-api.ps1 -NoFallback
```

---

### API port mismatch

`start-api.ps1` and `start-api.py` may set:

```powershell
$env:API_PORT
```

Manual port override:

```powershell
.\scripts\post-target.ps1 -Port 8001
.\scripts\get-open-ports.ps1 -TargetId 5 -Port 8001
```

---

### `{"detail":"Not Found"}` from open-ports API

This usually means the FastAPI route is not registered in the running uvicorn instance.

Check routes:

```powershell
.\scripts\check-api-routes.ps1
```

If port 8000 is an old instance:

```powershell
netstat -ano | findstr :8000
taskkill /PID <PID> /F
.\scripts\start-api.ps1
```

---

### Dispatcher stuck in `running`

Use stale-running recovery if configured:

```env
DISPATCHER_STALE_RUNNING_MINUTES=30
```

Or manually reset:

```sql
UPDATE scan_runs
SET status='pending'
WHERE status='running';
```

Use manual reset carefully.

---

### Kali has no internet

Do not assume Kali can install packages from the internet.

Transfer required binaries or packages from Windows using SCP.

Example:

```powershell
scp .\tool-file user@192.0.2.10:/home/kali/tools/
```

---

## Known Notes

1. Schema must match before INSERT.
2. `scan_results` should contain required fields such as `target_id` and `scan_type` if used by current code.
3. `POST /targets` should create target and initial work in the same transaction.
4. `open_ports` should avoid duplicate records for the same `scan_run_id + port + protocol`.
5. Do not start duplicate uvicorn or dispatcher instances.
6. Do not bypass approval workflow.
7. Do not bypass CommandTemplate rendering.
8. Do not introduce deferred architecture before MVP demonstration.

---

## Deferred Features

Not part of current MVP:

* Learning Engine
* Agent Memory
* Attack Graph
* Autonomous Exploitation
* msfconsole Integration
* sqlmap Integration
* Hydra Integration
* Payload Delivery
* Session Management
* Credential Attack Automation

Do not implement these until MVP demonstration is complete.

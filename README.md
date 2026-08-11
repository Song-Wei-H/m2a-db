# M2A Pentest DB

M2A is a governed autonomous security assessment orchestrator built with
FastAPI, PostgreSQL, and worker-side tool execution.

The project implements a deterministic-first and auditable execution loop for
authorized defensive security assessment workflows.

Authoritative project context:

```text
PROJECT_CONTEXT.md
```

If this README and `PROJECT_CONTEXT.md` conflict, follow `PROJECT_CONTEXT.md`.

## Safety Notice

This repository is for governed, authorized, defensive security assessment
only. Do not use it against systems without explicit authorization.

The platform is intentionally constrained by:

- allowlisted tools
- command templates
- scope validation
- approval gates
- ToolTask lifecycle controls
- local `subprocess(..., shell=False)` execution boundaries

Do not extend this repository with credential attacks, phishing delivery,
payload delivery, exploit-chain automation, EDR or antivirus bypass, arbitrary
shell execution, arbitrary argv execution, or unrestricted subprocess
execution.

## System Positioning

M2A is not a traditional vulnerability scanner. It coordinates approved tools
through governed `ToolTask` records, analyzes evidence, records decisions,
accumulates learning data, and exports reports.

Current execution source of truth:

- `tool_tasks`: worker execution queue and lifecycle source of truth
- `scan_runs`: initial scan trace and backward-compatible container

`POST /targets` creates both a `scan_runs` row and an initial `nmap_service`
`ToolTask`. Workers execute from `tool_tasks`.

## Current Runtime Flow

```text
Target
-> ScanRun trace
-> initial ToolTask
-> task_poller
-> governed tool execution
-> ToolResult
-> parser
-> normalized_results
-> evidence_confidence
-> learning_feedback
-> Risk Engine v3
-> DecisionScore
-> auto_loop
-> next governed ToolTask or stop
-> Report Generator
-> Report Export
```

Risk Engine v3 is a deterministic risk engine with learning-informed
adjustments. It is not an ML model. It considers CVSS, EPSS, KEV, runtime
signals, evidence quality, and learning feedback.

Offline model training modules exist for experiments only. They are not wired
into runtime decision making.

## Allowed Tools

Current allowlisted tools:

- `nmap_service`
- `httpx_basic`
- `nuclei_safe`
- `dirb_safe`
- `ssh-enum`
- `mysql-info`

Forbidden capabilities include:

- hydra or brute force
- password spraying
- credential stuffing
- phishing delivery
- payload delivery
- raw shell execution
- arbitrary argv execution

## Configuration

Copy `.env.example` to `.env` and adjust local values:

```powershell
Copy-Item .env.example .env
```

Important settings:

```env
DATABASE_URL=postgresql+asyncpg://m2a_user:replace_me@localhost:15432/m2a_pentest
KALI_WORKER_BASE_URL=http://192.0.2.10:9001
ALLOWED_SCOPES=192.0.2.0/24,203.0.113.0/24
ALLOWED_TOOLS=nmap_service,httpx_basic,nuclei_safe,dirb_safe,ssh-enum,mysql-info
ALLOWED_LLM_PROFILES=internal
```

Use documentation IP ranges in examples. Replace them only for an authorized
local environment.

## Install

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

## Database

Start PostgreSQL:

```powershell
docker compose up -d postgres
```

Schema bootstrap uses SQL files in `initdb/`. Existing databases should apply
migrations in filename order.

## Start Services

API:

```powershell
.\.venv\Scripts\python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Worker:

```powershell
.\.venv\Scripts\python -m worker.task_poller
```

Optional scan run dispatcher for backward-compatible scan trace processing:

```powershell
.\.venv\Scripts\python scan_run_dispatcher.py
```

Do not start duplicate API, worker, or dispatcher processes during local
testing.

## API Surface

Enabled routers:

- `app.api.targets`
- `app.api.open_ports`
- `app.routers.decisions`
- `app.routers.llm_tools`
- `app.routers.approval`

Key routes:

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/targets` | Create target, scan trace, and initial ToolTask |
| GET | `/targets/{target_id}/open-ports` | List target open ports |
| GET | `/targets/{target_id}/report` | Return structured target report |
| GET | `/targets/{target_id}/report/export` | Export report to JSON/HTML/PDF |
| GET | `/targets/{target_id}/report/download` | Generate and download one JSON/HTML/PDF artifact |
| GET | `/targets/{target_id}/report/latest` | Return latest exported HTML report |
| GET | `/targets/{target_id}/summary` | Dashboard target summary |
| GET | `/targets/{target_id}/tool-results` | Dashboard tool results |
| GET | `/targets/{target_id}/decisions` | Dashboard decisions |
| GET | `/targets/{target_id}/learning-feedback` | Dashboard learning feedback |
| GET | `/targets/{target_id}/run-status` | Runtime orchestration status |
| GET | `/dashboard/overview` | Aggregate dashboard counters |
| POST | `/decisions/run/{target_id}` | Run deterministic decision engine |
| POST | `/tools/llm-propose` | Submit governed LLM tool proposal |
| GET | `/approvals/pending` | List pending approval tasks |
| POST | `/approvals/{task_id}/approve` | Approve ToolTask |
| POST | `/approvals/{task_id}/reject` | Reject ToolTask |

## Report Export

Report export reads only `generate_target_report()` output. It does not query
the database or recalculate risk, decisions, learning, or ranking.

CLI:

```powershell
.\.venv\Scripts\python scripts\export_report.py --target 18 --format all
```

Outputs:

```text
reports/json/
reports/html/
reports/pdf/
reports/latest/
```

Generated reports are ignored by Git.

The export API also returns artifact size, SHA-256, and a download URL for each
generated format. The latest-report route is target-scoped and never falls back
to another target's global latest report.

## Tests

Run the full test suite:

```powershell
.\.venv\Scripts\python -m pytest tests -v
```

## Documentation

Architecture and research positioning:

- `docs/ARCHITECTURE.md`
- `docs/SYSTEM_WORKFLOW.md`
- `docs/RESEARCH_POSITIONING.md`
- `docs/LEARNING_FRAMEWORK.md`

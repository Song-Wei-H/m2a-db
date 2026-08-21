# M2A 受治理安全評估平台

M2A 是以 FastAPI、PostgreSQL 與受治理 Worker 組成的安全評估協調平台。它只適用於具有明確授權的內部實驗室、防守驗證與紅藍隊演練。

權威專案邊界以 [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) 為準；若本文件與該檔案衝突，依 `PROJECT_CONTEXT.md` 執行。

## 1. 安全邊界

M2A 不是可任意下指令的攻擊代理。LLM 或外部決策器只能提出結構化建議，實際執行仍受以下控制：

- 授權範圍（Scope）與目標驗證
- 工具白名單與固定命令模板
- 高風險操作人工核准
- ToolTask 狀態機、重複阻擋與最大輪數
- Worker 端再次檢查
- `subprocess(..., shell=False)`

禁止加入或使用任意 Shell、任意 argv、帳密暴力破解、密碼噴灑、釣魚、Payload 投遞、惡意持久化、EDR／防毒規避或未授權掃描。

## 2. 系統角色、設備與連線

最小部署可使用一臺 Windows 主機；完整內網演練建議分成三個角色：

| 角色 | 建議設備 | 服務／Port | 責任 |
|---|---|---|---|
| M2A 控制端 | Windows 開發機 | API `127.0.0.1:8000`、UI `127.0.0.1:5173` | UI、API、治理、報告與人工核准 |
| PostgreSQL | 同一 Windows 的 Docker Desktop | Host `localhost:15432` → container `5432` | Target、ToolTask、Evidence、Decision 與稽核紀錄 |
| Worker | Kali Linux 或安裝安全工具的受控主機 | 直接連 PostgreSQL；舊 Remote Runner 才使用 HTTP `/execute` | 從 ToolTask 取件並執行白名單工具 |
| 授權靶機 | 隔離 Lab VM／測試設備 | 依測試情境 | 只接受已書面授權的安全驗證 |

建議網路流向：

```text
瀏覽器 -> M2A UI :5173 -> M2A API :8000 -> PostgreSQL :15432
                                                ^
                                                |
                              Kali Worker ------+
                                   |
                                   +----> 授權靶機
```

### 雙網路工作方式

若內網可連 Kali 但不能連 GitHub，採兩階段操作：

1. 外網階段：安裝依賴、拉取／推送 GitHub；不要執行安全工具。
2. 內網階段：啟動 PostgreSQL、API、UI、Kali Worker 與授權靶機；所有變更先保留在本機 Git。
3. 切回外網後：確認不含 `.env`、報告、資料庫或秘密，再 push。

不要為了同時連線而開放 PostgreSQL、API 或 Worker 到公共網路。

## 3. 前置需求

控制端：

- Windows 10/11
- Python 3.11 或相容版本
- Docker Desktop（Linux containers）
- Node.js 與 pnpm（使用 UI 時）
- Git（只在版本同步時需要）

Kali Worker 需安裝 Repository 的 Python dependencies，以及實際允許使用的工具。目前 canonical allowlist 共九項；其中前三項是低影響、受治理的 Evidence Collector：

- `nmap_service`
- `httpx_basic`
- `nuclei_safe`
- `dirb_safe`
- `ssh-enum`
- `mysql-info`
- `tls_certificate`
- `http_security_headers`
- `dns_metadata`

缺少工具時應讓任務失敗並留下紀錄，不得改成任意 Shell 繞過。

## 4. 第一次安裝 SOP

### 4.1 建立 Python 環境

在 Repository 根目錄執行：

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Set-Location .\frontend
pnpm.cmd install
Set-Location ..
```

### 4.2 建立 `.env`

```powershell
Copy-Item .env.example .env
```

至少修改：

```env
POSTGRES_PASSWORD=請使用本機專用強密碼
DATABASE_URL=postgresql+asyncpg://m2a_user:同一密碼@localhost:15432/m2a_pentest

# 僅填入實際獲授權的內網／Lab 範圍
ALLOWED_TOOLS=nmap_service,httpx_basic,nuclei_safe,dirb_safe,ssh-enum,mysql-info,tls_certificate,http_security_headers,dns_metadata
ALLOWED_LLM_PROFILES=internal
```

規則：

- `.env` 不得 commit、貼入 Issue、Notion 或聊天。
- `POSTGRES_PASSWORD` 與 `DATABASE_URL` 中的密碼必須一致。
- 如果密碼含 `@`、`:`、`/` 等字元，需作 URL encoding。
- Kali Worker 不維護目標 CIDR；可達範圍由部署環境的 NDR、微分段與網路 ACL 控制。Worker 仍只接受固定 allowlist 工具，M2A 仍執行核准與任務治理。

### 4.3 API Key 要加在哪裡

M2A 的選用 advisory LLM runner 使用 OpenAI-compatible Chat Completions，讀取 `LLM_BASE_URL`、`LLM_MODEL`、`LLM_SEND_AUTH` 與選用的 `LLM_API_KEY`。可由 Launcher 的「API / LLM 設定」安全更新既有 `.env`；API Key 不得 commit、貼入 Issue、Notion 或聊天。

M2A 保留兩條受治理路徑：選用的內建 advisory runner 只接收最小 decision context；外部 LLM／決策服務則產生受 schema 約束的提案，再呼叫：

```text
POST http://<M2A_API>/tools/llm-propose
```

外部服務的供應商 API Key 應只存在該服務的 secret store；Launcher 設定的 `LLM_API_KEY` 只供現有內建 advisory runner 使用。兩者都不得放在瀏覽器、Notion、Git 或 M2A 前端。

### 4.4 啟動 PostgreSQL

先確認 Docker Desktop 已啟動，再執行：

```powershell
docker compose up -d postgres
docker compose ps
docker logs --tail 50 m2a-postgres
```

預期看到 `m2a-postgres` 為 `Up`，Host port 為 `15432`。

不要把 PostgreSQL 改成 `trust` authentication。PostgreSQL 官方文件說明 `trust` 會讓符合連線條件的人不需密碼即可宣告任意資料庫使用者身分；M2A 預設使用密碼驗證。參考：[PostgreSQL Trust Authentication](https://www.postgresql.org/docs/current/auth-trust.html)。

### 4.5 既有資料庫套用 migration

`initdb/` 只會在建立全新 PostgreSQL data volume 時自動執行。既有資料庫必須依檔名順序手動套用尚未執行的 migration。

Windows PowerShell 範例：

```powershell
Get-Content -Raw .\initdb\021_tooltask_lifecycle_alignment.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\024_approval_decision_audit.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\025_normalized_results_schema_alignment.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\026_remote_evidence_tools.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\027_execution_authorization.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\028_phase3_batch0_identity.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\029_phase3_batch1_dns_tls_identity.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\030_phase3_batch2_nmap_identity.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\031_phase3_batch3_httpx_identity.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest

Get-Content -Raw .\initdb\032_phase3_batch4_ssh_mysql_identity.sql |
  docker exec -i m2a-postgres psql -v ON_ERROR_STOP=1 -U m2a_user -d m2a_pentest
```

若 API 報告 `column tool_tasks.approved_at does not exist`，代表既有 volume 漏套 021；先執行 021，再執行 024。

若 API 報告 `password authentication failed for user "m2a_user"`，常見原因是 PostgreSQL volume 建立後才修改 `.env`。`POSTGRES_PASSWORD` 不會自動更新既有 role；請先確認 `.env` 中 `POSTGRES_PASSWORD` 與 `DATABASE_URL` 一致，再由資料庫管理者以受控方式更新 role 密碼。不要改用 `trust` 規避。

驗證欄位：

```powershell
docker exec m2a-postgres psql -U m2a_user -d m2a_pentest -c `
  "SELECT column_name FROM information_schema.columns WHERE table_name='tool_tasks' AND column_name IN ('proposal_reason','approval_decision_reason');"
```

Migration 027 建立 authorization-first 基礎；028–032 完成 Phase 3 Batch 0–4。
目前 8 個 action 由 Registry 決定 tier、template version 與 execution
identity：`http_security_headers`、`nuclei_safe`、`dns_metadata`、
`tls_certificate`、`nmap_service`、`httpx_basic`、`ssh-enum`、`mysql-info`。
其 ExecutionAuthorization 綁定 target、canonical parameters、parameter
hash、execution identity、template version、scope、expiry 與單次 execution，
Worker claim 在同一資料庫交易中消耗 authorization。歷史 approval 不會被
轉換成 authorization。`dirb_safe` 仍是明確的 legacy／未遷移工具，不得算入
8-action authorization-first coverage。

## 5. 每次啟動 SOP

Windows Launcher 可將本節的手動啟動流程整合為單一入口；設定、WSL／Remote Worker、Build、Log 與疑難排解請見 [`docs/M2A-Launcher.md`](docs/M2A-Launcher.md)。開發環境可執行：

```powershell
.\.venv\Scripts\python.exe -m m2a_launcher.main
```

Repository 只版本化 Launcher 原始碼與可重現建置腳本，不提交 EXE。需要 Windows 執行檔時，依 Launcher 文件建置；輸出位置是 `dist/M2A-Launcher/M2A-Launcher.exe`，不是 `m2a.exe`。執行檔應留在完整 Repository／部署目錄中，不能只複製單一 EXE，因為 Launcher 仍需使用 `docker-compose.yml`、`app/`、`frontend/`、`scripts/` 與 `.venv/`。

遠端 Kali 請在 Launcher 選單選擇「Worker 設定」→「Remote Kali」，或在 `.env` 設定：

```env
M2A_WORKER_MODE=remote
M2A_REMOTE_WORKER_URL=http://<Kali-內網-IP>:8000
```

Remote Worker 必須已在 Kali 上啟動，且 Windows 能取得其 `/health`；Remote 模式不會呼叫 WSL。

請開四個終端，順序如下。

### 終端 A：PostgreSQL

```powershell
docker compose up -d postgres
docker compose ps
```

### 終端 B：M2A API

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-api.ps1 -NoReload
```

預設：

- API：`http://127.0.0.1:8000`
- OpenAPI：`http://127.0.0.1:8000/docs`
- Schema：`http://127.0.0.1:8000/openapi.json`

若 8000 被占用，腳本可能改用 8001；UI 的 API Endpoint 也必須跟著改。

### 終端 C：前端 UI

```powershell
Set-Location .\frontend
pnpm.cmd install
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ..\scripts\start-ui.ps1
```

啟動器會自動尋找包含目前必要路由的 M2A API，忽略仍在監聽但版本過舊的程序，並顯示實際 UI URL。開發模式會將 API 路由代理到偵測出的相容 API，而不是假定固定使用 8000。

若 API 不在同一臺電腦：

1. UI → Settings → API Endpoint。
2. 填入 `http://<控制端內網IP>:8000`。
3. API 必須明確綁定該內網 IP，並以 Firewall 只允許管理端來源。

目前 API 沒有登入驗證及完整 CORS／TLS 部署層；不建議直接跨主機暴露。正式多機部署前必須加 reverse proxy、TLS、authentication、authorization 與來源限制。

### 終端 D：Worker

啟動前先查是否已有 pending 任務：

```powershell
docker exec m2a-postgres psql -U m2a_user -d m2a_pentest -c `
  "SELECT id,target_id,tool_name,status,approval_status FROM tool_tasks WHERE status='pending' ORDER BY id;"
```

確認所有目標均在授權範圍後，才啟動：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-worker.ps1
```

只跑一輪：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-worker-once.ps1
```

Kali 上請在已複製 Repository、建立 `.venv`、設定可連 PostgreSQL 的 `.env` 後執行：

```bash
./.venv/bin/python -m worker.task_poller
```

若 PostgreSQL 仍只映射在 Windows localhost，Kali 無法連線。跨主機連 DB 前必須：

- 使用固定內網 IP 與隔離 Lab 網段；
- 只允許 Kali IP 連 TCP 15432；
- 保持密碼驗證，不使用 `trust`；
- 調整 Docker port bind／Windows Firewall／PostgreSQL access rule；
- 不對 Internet 開放 15432。

舊的 `KALI_WORKER_URL`／Remote Runner 是另一條 HTTP `/execute` 路徑，不等同目前以 `tool_tasks` 為 source of truth 的 poller。沒有明確部署 Remote Runner 時不要假設它已存在。

## 6. 安全 Smoke Test

不建立目標、不啟動工具的控制面檢查：

```powershell
Invoke-RestMethod http://127.0.0.1:8000/openapi.json
Invoke-RestMethod http://127.0.0.1:8000/dashboard/overview
Invoke-RestMethod http://127.0.0.1:8000/approvals/pending
```

完整測試：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
Set-Location .\frontend
pnpm.cmd build
```

只有在授權靶場已確認後，才能建立目標：

```powershell
.\scripts\post-target.ps1 -Target 192.168.56.10 -BaseUrl http://127.0.0.1:8000
```

`POST /targets` 會立即建立初始 `nmap_service` ToolTask；不要把它當成純資料輸入。若 Worker 正在運行，任務可能開始執行。

## 7. 人工核准 SOP

1. 開啟 UI → Approval Center，或呼叫 `GET /approvals/pending`。
2. 核對 target、scope、tool、proposal rationale 與 policy gate rationale。
3. 核對書面授權、時間窗、影響、停止條件與資料處理限制。
4. 輸入不可空白的人工作決策理由。
5. 核准或拒絕。

目前 `approved_by` 仍由 UI／client 提供，不是可信身分來源。未加入 authentication／RBAC 前，不可把此介面當成生產級身分稽核。

## 8. API 一覽

| Method | Path | 用途 |
|---|---|---|
| POST | `/targets` | 建立 Target、ScanRun 與初始 ToolTask |
| GET | `/dashboard/overview` | 控制台統計 |
| GET | `/targets/{id}/run-status` | 任務狀態與輪次 |
| GET | `/targets/{id}/report` | 結構化報告 |
| GET | `/targets/{id}/report/export?format=all` | 匯出 JSON／HTML／PDF |
| POST | `/decisions/run/{id}` | 執行確定性決策引擎 |
| POST | `/tools/llm-propose` | 接收外部 LLM 的受治理 JSON 提案 |
| GET | `/approvals/pending` | 待人工核准任務與上下文 |
| POST | `/approvals/{task_id}/approve` | 核准並保存理由 |
| POST | `/approvals/{task_id}/reject` | 拒絕並保存理由 |

`ExecutionAuthorization` 是 M2A 伺服器內部治理產物，不提供讓 client／LLM
直接建立 grant 的公開 endpoint。外部決策器只能透過 `/tools/llm-propose`
提交結構化提案；M2A 再依 Registry、policy 與 approval 狀態建立或拒絕
authorization，caller 提供的 risk 值不能降低 Registry tier。

提案範例：

```powershell
.\scripts\propose-llm-tool.ps1 `
  -Tool httpx_basic `
  -Target 192.168.56.10 `
  -Reason "確認已授權 Web 服務的基本回應" `
  -RiskLevel low `
  -Profile internal `
  -TargetId 1 `
  -BaseUrl http://127.0.0.1:8000
```

## 9. 報告

```powershell
.\.venv\Scripts\python.exe scripts\export_report.py --target 18 --format all
```

輸出位於 `reports/json/`、`reports/html/`、`reports/pdf/` 與 `reports/latest/`，不應 commit。

## 10. 停止與復原

API、UI、Worker：在各終端按 `Ctrl+C`。

停止 PostgreSQL但保留資料：

```powershell
docker compose stop postgres
```

重新啟動：

```powershell
docker compose start postgres
```

不要執行 `docker compose down -v`，除非已確認要刪除資料庫 volume 且有備份與人工核准。

## 11. 常見問題

### Docker Images 有 postgres，但服務不能連

Image 只代表映像存在。以 `docker compose ps` 確認 container 為 `Up`；再查 `docker logs m2a-postgres`。

### PowerShell 不允許執行 `.ps1`

使用單次 process-scoped bypass：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-api.ps1
```

這不會修改全機執行原則。

### API 啟動但 UI 無資料

- 查看 API 實際是 8000 還是 8001。
- UI Settings 的 API Endpoint 必須一致。
- 執行 `scripts/check-api-routes.ps1`。

### Kali 連不到 PostgreSQL

- Windows 的 `localhost:15432` 只供本機使用。
- 檢查 Docker bind、Windows Firewall、Kali 到 Windows 的路由與 PostgreSQL access rule。
- 僅允許 Kali 的固定內網 IP，不使用 `trust`，不對 Internet 開放。

## 12. 證據與成熟度

目前功能分支的自動驗證涵蓋後端、Launcher、CVE correlation／validation／report 與前端 production build。精確測試結果應以該 commit 的 CI 或本機測試輸出為準，不在 README 固定保存容易過期的 passed 數量。本機 smoke test、資料庫 migration 與遠端 Kali 工具執行結果只代表執行當下的環境，不等於正式 GADE 研究結果或生產安全認證。

詳細資料：

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/SYSTEM_WORKFLOW.md`](docs/SYSTEM_WORKFLOW.md)
- [`docs/CAPABILITY_AUDIT_2026-08-13.md`](docs/CAPABILITY_AUDIT_2026-08-13.md)
- [`docs/RESEARCH_POSITIONING.md`](docs/RESEARCH_POSITIONING.md)
# Deployment target-scope mode

When target authorization is enforced externally by NDR and microsegmentation, use `ENFORCE_TARGET_SCOPE=false`. M2A will accept syntactically valid IP addresses and hostnames while retaining tool and approval controls. Set it to `true` to enforce `ALLOWED_SCOPES`, `ALLOWED_HOSTNAMES`, and `ALLOWED_DOMAIN_SUFFIXES` locally. Restart M2A processes after changing this setting.

Use `scripts/start-api.ps1` as the normal API entry point. It enforces one compatible M2A API instance by default. The UI launcher also fails closed if multiple compatible APIs are detected, preventing stale runtime configuration from consuming tasks.

## CVE evidence citations

CVE matches are reported as governed candidates with official claim-level references. M2A links the NVD and CVE Program record for identity/CVSS context, FIRST EPSS when an EPSS value is present, and CISA KEV when KEV membership is asserted. Product-only matching remains `SOURCE_CLAIM / HIGH_VALIDATION_PRIORITY / VERSION_UNRESOLVED`; version is filtering evidence rather than a validation prerequisite, and a candidate is not a confirmed target vulnerability.

In Report Center, `下載 HTML`, `下載 PDF`, `下載 JSON`, and `全部下載` first generate verified server artifacts and then immediately hand the resulting files to the browser download manager. Server copies remain under `reports/` for lifecycle and integrity tracking.

## Local CVE read-model

M2A can use a rebuildable SQLite CVE index plus an in-process LRU cache without running Valkey:

```env
CVE_LOCAL_INDEX_ENABLED=true
CVE_LOCAL_INDEX_PATH=data/cve_index.sqlite3
CVE_QUERY_SAFETY_LIMIT=5000
CVE_REPORT_CANDIDATE_BUDGET=50
```

Rebuild it from PostgreSQL authority without external network access:

```powershell
.\.venv\Scripts\python.exe scripts\sync_cve_intel.py --rebuild-local-index
```

Normal CVE synchronization rebuilds the index automatically unless `--skip-local-index` is supplied. Lookup order is SQLite/LRU first and PostgreSQL fallback on missing, empty, disabled, or unreadable local state. The index is disposable and excluded from Git; PostgreSQL remains the evidence/provenance authority. The query safety limit is not a report Top-N rule: all mandatory KEV/exact-version/high-confidence critical/high-EPSS candidates survive, while lower-confidence product-only candidates are risk-ranked and summarized to the report budget.

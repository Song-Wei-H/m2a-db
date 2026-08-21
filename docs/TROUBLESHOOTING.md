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
# Launcher 測試無法建立 pytest 暫存目錄

若 Launcher 測試在 fixture setup 顯示 `PermissionError: [WinError 5]` 且路徑位於 `%LOCALAPPDATA%\Temp\pytest-of-*`，這是目前 shell 的暫存目錄 ACL 問題，不代表測試 assertion 失敗。改用 Repository 內受控暫存目錄：

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_launcher.py -v --basetemp .tmp\pytest-launcher
```

若連 Repository 內目錄也無法寫入，停止測試並檢查 ACL；不要用系統管理員權限或放寬整個 Repository 權限規避。

## Launcher runtime preflight 找不到 Docker 或 Kali Linux

- Docker 顯示 named pipe 不存在：啟動 Docker Desktop，等待 Linux Engine ready，再執行 `docker version`；Launcher 不會自行安裝或繞過 Docker。
- `wsl.exe --list --quiet` 沒有設定的 `M2A_WSL_DISTRO`：安裝並準備 Kali Linux，或修正 `.env` 中的實際 Distro name。不要把 `docker-desktop` 當作 Kali Worker。
- 從子目錄執行驗證命令時，使用 Repository 根目錄的絕對 Python path，避免 `.venv` 被解析到錯誤目錄。

## Windows PowerShell 5.1 解析 UTF-8 build script 失敗

症狀是中文 literal 亂碼，接著出現 `ParserError` 或 missing string terminator。PowerShell 5.1 對 UTF-8 無 BOM source 有 legacy encoding 限制；`scripts/build-launcher.ps1` 因此保持 ASCII-only。Launcher 的繁體中文 UI、subprocess decoding 與 UTF-8 log 由 Python layer 處理。不要用變更全機 code page 或重寫 protocol／identifier 的方式規避。

## EXE API 設定 smoke 沒有建立 `.env`

不要用 PowerShell pipeline 模擬 Windows `getpass`；redirected stdin 不是互動 console。使用 PTY，並在輸入任何假 Key 前確認 Launcher 顯示隔離 `.env` 的 First Run 警告。Frozen project root 以有效 cwd 優先；若畫面沒有預期 First Run，立即離開並檢查 root identity，不得繼續寫入。
# Confidence-driven CVE regression notes (2026-08-21)

- Symptom: a unit-test `SimpleNamespace` raised `AttributeError` after optional
  product/source trace fields were added to `CveRiskSummary`.
- Cause: trace enrichment initially assumed every ORM-like test row exposed all
  optional correlation fields, while the established test double only modeled
  scoring inputs.
- Resolution: optional trace fields use `getattr(..., None)`; scoring fields retain
  their existing contract. Targeted CVE/report/task regression: 31 passed.
- Prevention: new trace-only fields must remain optional at the scoring boundary.
# Dispatcher pending ToolTask stalls on PostgreSQL outer-join lock (2026-08-21)

- Symptom: UI shows `nmap_service` pending with zero running Workers although Backend and remote Worker preflight are healthy.
- Error: `FeatureNotSupportedError: FOR UPDATE cannot be applied to the nullable side of an outer join`.
- Cause: the pending-task selector joined nullable `execution_authorizations` and emitted an unqualified `FOR UPDATE SKIP LOCKED`.
- Resolution: both global and target-scoped selectors now emit `FOR UPDATE OF tool_tasks SKIP LOCKED`; `_claim_task` continues to lock and consume the authorization separately.
- Validation: generated PostgreSQL SQL regression PASS; live selection returned target 39 task 142 without error or state change; focused 38 passed; full 438 passed.
- Operational note: restart the Dispatcher so its Python process imports the corrected module. A pending authorized task may execute after restart.
# Decision card always says tool was not adopted (2026-08-21)

- Symptom: a Decision card selects `httpx_basic` but always displays `未採用工具：已停用：端點未開放`.
- Cause: the frontend string was a hard-coded placeholder and was unrelated to Decision, OpenPort, ToolTask, or rejection evidence.
- Resolution: Decision cards now correlate `decision_score_id` and `next_tool` with report ToolTasks. They show adopted pending/running/completed/failed state, a real rejection reason, or explicit no-lineage data. The unsupported fixed claim was removed.
- Validation: TypeScript/Vite production build PASS (2287 modules), built asset contains the new lineage states and not the old text, backend regression 438 passed.
- Known tooling gap: `npm run lint` cannot start because the repository uses ESLint 9 without `eslint.config.js`; no lint result is claimed.

# M2A Windows Launcher

`M2A-Launcher` 是薄型 Runtime Orchestrator。它依序檢查 Docker／PostgreSQL、啟動 FastAPI Backend、Kali Worker、`worker.task_poller` Dispatcher 與 Vite Frontend，全部 Health Check 通過後才開啟瀏覽器。它不修改 GADE、Decision Engine、Tool Registry、Approval Gate、ToolTask、ToolResult 或 Worker `/execute` contract。

## 架構與啟動順序

```text
M2A-Launcher.exe
  -> Docker Engine -> PostgreSQL pg_isready
  -> FastAPI /health
  -> WSL Kali -> scripts/start-worker.sh -> kali_worker.app /health + /execute
  -> worker.task_poller (Dispatcher)
  -> Vite Frontend
  -> Browser
```

Frontend 目前仍是獨立 Vite process；Repository 尚未建立由 FastAPI 提供 production `dist` 的 routing contract，因此 Launcher 不進行該項架構重構。

## 設定

Launcher 沿用 Repository 根目錄 `.env`。設定範例見 `.env.example`。`M2A_WORKER_MODE=wsl` 會使用 `wsl.exe -d <distro> -- bash -lc ...` 啟動 Worker；`remote` 不啟動 WSL，只檢查 `M2A_REMOTE_WORKER_URL/health`。所有等待時間都有 timeout。

遠端 Kali 範例：

```env
M2A_WORKER_MODE=remote
M2A_REMOTE_WORKER_URL=http://192.0.2.10:8000
```

請將文件保留位址替換為已授權 Lab 中的 Kali 內網位址，並先在 Kali 啟動 Remote Worker。Remote 模式不會透過 SSH 部署程式，也不會自行啟動遠端服務。

`M2A_WSL_WORKER_DIR` 必須是 WSL 中含本 Repository 與 `.venv` 的目錄。Launcher 不會自動安裝 WSL、Kali Linux、Python 或安全工具。

`M2A_LAUNCHER_DEBUG=false` 只顯示簡潔中文事件；設為 `true` 顯示 PID、URL、Worker Mode、WSL Distro 與 HTTP status 等技術資訊。Log 位於 `logs/launcher-YYYYMMDD.log`，UTF-8 編碼，命令中的 password、token、API key 與 Authorization 會遮罩。

## API／LLM 與 Worker 設定選單

Launcher 主選單可啟動 M2A、編輯 API／LLM、編輯 Worker、顯示 masked 設定或離開。LLM 權威欄位為 `LLM_API_KEY`、`LLM_MODEL`、`LLM_BASE_URL`、`LLM_SEND_AUTH`；Provider 是現有 OpenAI-compatible Chat Completions client，不新增第二套 config。

API Key 使用 `getpass` 輸入且不 echo。`.env` 不存在時先複製 `.env.example`；存在時只 line-based 更新指定欄位，保留 comments、unknown／unrelated variables 與順序，修改前覆寫單一 `.env.backup`。`.env.*` 已由 `.gitignore` 排除。顯示設定只輸出 masked key；設定成功不代表 API connectivity 已驗證，也不會自動消耗 token。

## 執行、停止與防重複

開發環境：

```powershell
.\.venv\Scripts\python.exe -m m2a_launcher.main
```

關閉 console 或按 `Ctrl+C` 時，Launcher 只停止本次建立並持有 handle 的 process；PostgreSQL container 與資料 volume 預設保留。第二次啟動會開啟既有 UI，不建立第二套 process。連接埠若由非 M2A process 使用，Launcher 回報 PID 並停止，不會自動終止該 process。

## Build

PyInstaller 是 release build dependency，不加入 M2A runtime requirements；版本固定於 `requirements-launcher-build.txt`。先在受控 build environment 安裝，再執行：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-launcher-build.txt
.\scripts\build-launcher.ps1
```

輸出為 `dist/M2A-Launcher/M2A-Launcher.exe`（`--onedir`）。不使用 `--onefile`、runtime executable extraction、encoded command、安全產品排除或 bypass。正式企業 release 應使用可信任憑證進行 Authenticode Code Signing；本 Repository 不建立自簽或偽造憑證。

`dist/` 與 EXE 刻意由 Git 忽略；GitHub 儲存的是原始碼與建置方式，而不是未簽章 binary。請保留完整 `dist/M2A-Launcher/` onedir 內容，並從 Repository／部署根目錄啟動；不能只搬移單一 EXE，因為 Launcher 仍需存取專案檔案、Python 環境及前端依賴。

## 測試與疑難排解

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_launcher.py -v
.\.venv\Scripts\python.exe -m pytest -q
Set-Location frontend; pnpm.cmd build
```

WSL 實機 smoke test：確認 Distro、Repository、Kali `.venv` 與工具已就緒，再以開發命令啟動。若顯示找不到 Distro，執行 `wsl.exe --list --quiet` 並使 `M2A_WSL_DISTRO` 完全相符。Timeout 或原始 exception 的完整 stack trace 請查看 Launcher log。

## AV／EDR 考量

Launcher 使用可見 console、PyInstaller `--onedir`、直接 `wsl.exe` argv、固定 component command、無 encoded payload、無 runtime extraction、無 AV／EDR／AMSI／Firewall bypass。正式發行再加可信任 Authenticode 簽章。

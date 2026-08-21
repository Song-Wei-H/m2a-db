# M2A Launcher Build Log

## 2026-08-21 — 現況盤點

- 目的：確認實際啟動架構與安全邊界。
- 命令：`git status`、`rg --files`、讀取 `PROJECT_CONTEXT.md`、啟動腳本、Docker／Worker／Frontend 設定。
- 結果：確認 Backend=FastAPI/Uvicorn、DB=Docker PostgreSQL、Frontend=Vite、Dispatcher=`worker.task_poller`、Kali HTTP Worker=`kali_worker.app`。
- 成功：是；版本：`main@a17a5e9`；修改檔案：無。

## 2026-08-21 — Launcher 實作

- 目的：建立繁體中文 Windows Launcher、Debug、UTF-8 log、WSL／Remote mode、PID 管理、timeout、single-instance 與 packaging。
- 命令：以受控 patch 新增 `m2a_launcher/`、scripts、tests 與文件，並新增 Backend `/health`。
- 結果：程式碼已建立，等待測試與 runtime validation。
- 成功：待驗證；版本：Launcher 0.1.0；修改檔案：見 Git diff。

## 2026-08-21 — 第一輪單元測試

- 目的：執行語法檢查與 Launcher 單元測試。
- 命令：`python -m py_compile ...`、`python -m pytest tests/test_launcher.py -v`。
- 結果：6 passed、4 setup errors；pytest 無法建立系統暫存目錄，且 `py_compile` 無法建立 `m2a_launcher/__pycache__`。
- 原始錯誤：`PermissionError: [WinError 5] Access is denied`。
- 分類：Environment／Windows ACL；不是 Launcher assertion failure。
- 修正：改用 AST syntax parse，pytest 使用 Repository 內 `.tmp/pytest-launcher` 作為 `--basetemp`。
- 成功：否；修改檔案：本 Build Log、`docs/TROUBLESHOOTING.md`。

## 2026-08-21 — 測試與環境能力驗證

- 目的：執行 Launcher／既有 regression、Frontend build，並檢查 Docker、WSL 與 packaging capability。
- 命令：`pytest tests/test_launcher.py`、`pytest -q`、`pnpm build`、`docker version`、`docker compose ps`、`wsl.exe --list --quiet`。
- 結果：Launcher 10 passed；完整 pytest 412 passed；Vite production build 成功。Docker Engine pipe 不存在；WSL 只有 `docker-desktop`，沒有 Kali Linux。
- 原始 Docker 錯誤：`failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine`。
- Warning／限制：PostgreSQL、Backend、WSL Worker 與 Browser 的完整 runtime smoke test 無法執行。
- 命令錯誤：從 `frontend` 目錄使用 `.venv` 相對路徑，PowerShell 回報 executable not recognized；改用 Repository 根目錄或絕對 interpreter 路徑。
- 預防：跨工作目錄驗證一律使用絕對 interpreter path；runtime smoke 前先檢查 Docker Engine 與 `wsl.exe --list --quiet`。
- 成功：partial；修改檔案：Frontend `dist`（Git ignored）、本 Build Log。

## 2026-08-21 — Packaging 第一次執行

- 目的：以 PyInstaller 6.22.2 建立 `--onedir` executable。
- 命令：`powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-launcher.ps1`。
- 結果：失敗；Windows PowerShell 5.1 將 UTF-8 無 BOM 的中文 script literal 錯誤解碼，造成 `ParserError` 與 missing string terminator。
- 原始錯誤類型：`ParentContainsErrorRecordException`／`ParserError`。
- 根本原因：PowerShell 5.1 對 UTF-8 無 BOM source encoding 的 legacy 行為。
- 修正與預防：build wrapper 保持 ASCII-only；繁體中文 Launcher UI 由 Python UTF-8 console layer 負責，不交由 PowerShell source literal。
- 成功：否；修改檔案：`scripts/build-launcher.ps1`、本 Build Log、`docs/TROUBLESHOOTING.md`。

## 2026-08-21 — 最終 Build 與驗證

- 目的：驗證 frozen root discovery、安全 WSL quoting、graceful shutdown、完整 regression 與 EXE metadata。
- 命令：Launcher pytest、完整 pytest、`scripts/build-launcher.ps1`、執行最終 EXE preflight、`Get-FileHash`、VersionInfo 檢查。
- 結果：Launcher 12 passed；完整 414 passed；PyInstaller build PASS；中文 preflight PASS；metadata PASS。
- EXE：`dist/M2A-Launcher/M2A-Launcher.exe`；SHA-256 `7FA89DC0CA096C7D25016A893D2580055ADEE9BAE3195E4A2C4B8C27D8C91EE3`。
- Runtime 限制：Docker Engine 未執行且沒有 Kali Linux Distro，完整 runtime validation 為 NOT EXECUTED。
- 成功：partial（程式、測試、build 與 fail-path smoke 成功；完整 runtime 受環境限制）。

## 2026-08-21 — API／`.env` 設定功能實作

- 目的：讓 Launcher 以繁體中文選單安全更新現有 LLM 與 Worker `.env` 欄位。
- 權威設定：`LLM_API_KEY`、`LLM_MODEL`、`LLM_BASE_URL`、`LLM_SEND_AUTH`；Provider 為現有 OpenAI-compatible client。
- 實作：line-based targeted update、comments／unknown variables preservation、單一 `.env.backup`、masked input／display、First Run 與 WSL／Remote Worker menu。
- 安全：secret 不進 console、debug、log、command line 或 test fixture；`.env.*` 已由 `.gitignore` 保護。
- 結果：程式碼完成，等待 tests、Frontend regression、EXE build 與 temporary `.env` smoke。
- 成功：待驗證；修改檔案：`m2a_launcher/`、`.env.example`、README、tests／docs（後續步驟）。

## 2026-08-21 — EXE Configuration Smoke 第一次執行

- 目的：在隔離 `.tmp` project root 驗證 First Run、masked input、`.env` reload 與 masked display。
- 第一次方法：PowerShell redirected stdin；Windows `getpass` 未接受 redirected input，未建立 `.env`，masked assertion 失敗。
- PTY 診斷：EXE frozen root discovery 先選到 `dist` 上層真實 Repository，而非有效隔離 cwd；只執行「離開」，未進入設定，真實 `.env` 未修改。
- 根本原因：frozen candidate ordering 將 executable ancestors 放在 cwd 前；原測試未模擬 `sys.frozen`。
- 修正：有效 cwd 改為第一優先，加入 frozen-root regression；EXE smoke 必須使用 PTY，不以 redirected `getpass` 結果代表互動 console。
- 成功：否（安全中止並修正）；修改檔案：`m2a_launcher/config.py`、Launcher tests、Build Log。

## 2026-08-21 — API／`.env` 設定最終驗證

- 目的：完成 regression、Frontend、EXE rebuild 與隔離 PTY configuration smoke。
- 命令：Launcher／Config pytest、完整 pytest、`pnpm build`、`scripts/build-launcher.ps1`、隔離 PTY EXE workflow、masked `.env` assertion。
- 結果：Launcher 25 passed，其中 Config 12 passed；完整 427 passed；Frontend PASS；PyInstaller onedir PASS。
- EXE smoke：First Run PASS、`getpass` no-echo PASS、API 設定 PASS、`.env` update／reload PASS、masked display `tes****6789` PASS。
- Secret：完整測試 Key 未出現在 console output、Launcher log、debug、command line argument 或文件；smoke temporary 目錄經 exact-path／reparse-point 驗證後移除。
- EXE SHA-256：`53CBA52DC0FAB29BE9A6DF3206326B0255BE59256DDF240C163DE677FBA1D399`。
- 成功：是；限制：未執行 LLM connectivity request，避免額外 token／外部行動。
# 2026-08-21 防閃退修正

- 目的：讓使用者能看見 Docker／WSL／Backend 啟動錯誤，不因 Console 關閉而誤認閃退。
- 修改：`m2a_launcher/main.py` 加入 error pause 與 EOF-safe menu handling；新增兩個 regression tests。
- 結果：focused 27 passed；PyInstaller 6.22.2 rebuild PASS；互動與非互動 EXE smoke PASS。

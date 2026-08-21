# M2A Launcher Installation Report

## 版本與環境

- Repository：`main@a17a5e92997c87fab5a924ffa2d8433df65234a8`（實作前基準）
- Windows：Windows 11 build 26200
- Python：3.14.4
- PyInstaller：6.22.2；release-only dependencies 見 `requirements-launcher-build.txt`
- Frontend：Vite 6.4.3
- Launcher：0.1.0，PyInstaller `--onedir`

## 安裝與 Build

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-launcher-build.txt
.\scripts\build-launcher.ps1
```

輸出：`dist/M2A-Launcher/M2A-Launcher.exe`。最終 EXE SHA-256：`53CBA52DC0FAB29BE9A6DF3206326B0255BE59256DDF240C163DE677FBA1D399`。

## 驗證

- Launcher tests：25 passed，其中 API／`.env` Config tests 12 passed。
- 完整 pytest：427 passed。
- Frontend production build：PASS。
- PyInstaller onedir build：PASS。
- EXE metadata：ProductName `M2A`、FileDescription `M2A Launcher`、FileVersion／ProductVersion `0.1.0`。
- EXE preflight：PASS；繁體中文正確顯示，Docker Engine 不可用時 exit code 1，UTF-8 log 保存 `LauncherError` stack trace。
- EXE configuration smoke：PASS；隔離 `.env`、Windows PTY masked input、targeted update、reload 與 masked display 均通過，未修改真正 `.env`。
- Docker／PostgreSQL／Backend／Frontend／WSL／Worker／Browser 完整 runtime：NOT EXECUTED。Docker Desktop Engine 未執行，且 WSL 只有 `docker-desktop`、沒有 Kali Linux。

## 問題、修正與限制

PowerShell 5.1 UTF-8 無 BOM、pytest Temp ACL、redirected `getpass` 與 frozen-root priority 問題、修正與預防記錄於 `docs/M2A-Launcher-Lessons.md`、`docs/TROUBLESHOOTING.md` 與 `docs/M2A-Launcher-Build-Log.md`。Launcher 不安裝 WSL／Kali／Python／工具，不刪 container／volume，不繞過安全控制。

## Rollback／Recovery

Launcher 為 additive implementation。Rollback 時移除 Launcher package、scripts、tests、docs 與 `/health` endpoint 變更即可；不得刪除 PostgreSQL container、volume、evidence、ToolResult、DecisionScore 或 experiment data。若 Launcher 中止，只會管理自己建立的 process；PostgreSQL 預設保留。

## 相關文件

- SOP／Architecture／Checklist：`docs/M2A-Launcher.md`
- Build history：`docs/M2A-Launcher-Build-Log.md`
- Known Issues／Troubleshooting：`docs/TROUBLESHOOTING.md`
- Lessons：`docs/M2A-Launcher-Lessons.md`

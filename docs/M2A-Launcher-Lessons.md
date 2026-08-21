# M2A Launcher Lessons

## Windows encoding 與 sandbox 測試路徑

- `repeat_count`: 1
- 症狀：Windows PowerShell 5.1 將 UTF-8 無 BOM 的中文 build script literal 解碼錯誤；受限執行環境也拒絕 pytest 寫入預設 Temp。
- 已確認原因：PowerShell 5.1 legacy source encoding；測試 process 的 filesystem sandbox。
- 修正：build wrapper 保持 ASCII-only；使用 Python 設定 UTF-8 console／log／subprocess decoding；pytest 使用核准的 repository basetemp。
- 為何有效：避免由 PowerShell 來源解析中文，將使用者介面 encoding 集中到可測試的 Python layer。
- 驗證：Launcher 12 passed、完整 pytest 414 passed、最終 EXE 中文 preflight 顯示正常。
- 預防：跨 working directory 使用絕對 interpreter；PowerShell 5.1 wrapper 不放非 ASCII literal；不得以放寬 ACL 或修改全機 code page 規避。

## Frozen EXE 設定根目錄與 getpass smoke

- `repeat_count`: 1
- 症狀：redirected stdin 無法代表 Windows `getpass` 互動；frozen EXE 先選到 executable ancestor Repository，而非隔離 smoke cwd。
- 已確認原因：smoke harness 未使用 PTY；frozen candidate order 將 cwd 排在 executable ancestors 之後。
- 修正：有效 cwd 優先；新增 `sys.frozen` regression；EXE masked-input smoke 使用 PTY。
- 驗證：Launcher 25 passed、完整 427 passed、隔離 EXE API configuration／reload／masked display PASS。
- 預防：任何會寫 `.env` 的 frozen smoke 必須先證明 project root identity，且只在隔離 cwd 執行。
# 2026-08-21：雙擊啟動錯誤看似閃退

- 現象：Docker Engine 不可用時 Launcher 正確輸出錯誤並以 exit 1 結束，但由檔案總管雙擊啟動的 Console 會立即關閉；非互動 stdin 另會產生未處理 `EOFError`。
- 修正：互動啟動失敗後顯示「按 Enter 關閉視窗」；所有頂層選單輸入捕捉 EOF 並以繁體中文安全退出。
- 驗證：Launcher focused tests 27 passed；PyInstaller rebuild PASS；互動 PTY 顯示 Docker 建議後停留等待 Enter；無輸入 EXE smoke 無 traceback。

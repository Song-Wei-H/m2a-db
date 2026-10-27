# GADE A/B/C 工程就緒報告（2026-10-27）

狀態：`BLOCKED_FOR_FORMAL_COLLECTION`。此報告只描述本輪實際核對與測試，不能作為正式實驗樣本。

## Git 與範圍

- 公司原工作樹：`C:\Users\p2166\m2a-db`，`experiment/gade-seven-level-v1` / `e0e62b2d8bb8e765366dc8025387cf95c2a33753`；原有未追蹤 `worker-deployment/` 保留，未 Reset/Clean。獨立整合工作樹：`C:\Users\p2166\Documents\Codex\m2a-gade-abc-integration`，`integration/gade-abc-20261027` / `33f68562219885318b8224322d9a9398d998cfb2`。
- GitHub 核對：`main@8609b90f1c22214024f4ac7c647118c0b5379c4f`、`experiment/gade-seven-level-v1@e0e62b2d8bb8e765366dc8025387cf95c2a33753`、`home-advanced-policy@afab9cb0fe012466007ebee25eb41acbefb493b3`。自遠端候選祖先 `c88aba51581b141e63b23280454b601edf63dbd8` 選擇性移植，未 Merge 全分支、未 Push、未部署。較新 policy hardening commits 未納入本次整合，須單獨安全審查。
- OSV `feature/osv-enrichment` / `166dc61cae561273afe62b1678df7680f88f93e1` 未移植；ARTEX 未引入。

## 七層能力與治理鏈

| 深度 | 本輪程式與證據狀態 | Live 限制 |
|---|---|---|
| L1 | 原分支既有八個已註冊 Action；本輪預設停用回歸包含 Worker/Authorization/Trace/Report。 | 本輪未重跑 L1 Worker E2E。 |
| L2 | 原本固定 T1078 測試帳號 Action/Target；Report 現能從已持久化 NormalizedResult 顯示 T1078 受控模擬。 | 未做公司端新 Live Run；不能推論既有 Run 的來源列完整。 |
| L3 | 原本固定 T1059.006 Python Action/Target；Report 現能從已持久化 NormalizedResult 顯示 T1059.006 受控模擬。 | 未做公司端新 Live Run。 |
| L4 | 選擇性移植固定可撤銷合成角色租約、Contract、Worker Handler、Normalizer、Target 狀態及離線檢測；預設停用。 | 家用 localhost Scope/Identity，未在公司 Worker/Target 驗證，無 Live Alert。 |
| L5 | 固定非秘密 Canary 與模擬可見度，具有離線狀態/規則測試；預設停用。 | 不代表真實憑證取得或防禦規避，無公司 Live Trace。 |
| L6 | 固定邏輯節點發現/Session，具有離線狀態/規則測試；預設停用。 | 邏輯節點非獨立網路主機，來源/目的獨立 Live 事件未驗證。 |
| L7 | 合成 Collection、本地 NOOP、邏輯 receiver digest、可撤銷 impact，具有離線測試；預設停用。 | Receiver 非獨立服務，無外部 C2/外傳或 Live Alert。 |

Proposal/Authorization 分離、D1/D3 超深度拒絕、個別 Approval/PENDING、Worker 預設能力停用、受控 Handler、Normalizer、Reset/藍隊離線規則有定向測試。此測試範圍不能替代跨程序 `Evidence → Proposal → Decision → Grant → ToolTask → Worker Receipt → ToolResult → NormalizedResult → Report/Trace` Live E2E，也不能證明 Worker 遠端版本已更新。沒有因測試放寬 Scope、Grant 或 Approval。

## 真正執行的測試與 Evidence

- Windows Host Python `.venv`、不可連線的合成 DB URL、獨立新 pytest basetemp，未接觸正式 DB、Worker 或 Target：候選合成契約/治理/Target/Normalizer/Report `53 passed, 1 skipped`；預設停用 Worker/ExecutionAuthorization/Trace/Report `66 passed, 1 skipped`；多輪治理/Approval/ToolTask 狀態/Reporting `37 passed`。原 Sandbox 的 pytest 暫存清理 `WinError 5` 不是產品測試結果。
- JUnit：`reports/test-runs/host-4efb5eab32dd40f9acdeb12da0355230/junit.xml`、`reports/test-runs/host-default-58ccf8aab6f34b8fada2e09c9ea9c85f/junit.xml`、`reports/test-runs/host-governance-20261027/junit.xml`。第三份 SHA-256：`7f3548bbef2d732cf56237f03687abaaf34c9512800cd0e4039708f813e42248`。程式/前兩份 JUnit 雜湊清單：`reports/test-runs/integration-20261027-sha256.json`，自身 SHA-256 `045a0f016be688cc82f60f3ca502ca1bfd0b18f958efa9eb4a3c76d79a166ee2`。
- `git diff --check` 通過，沒有提交密碼、Token、DB dump 或測試暫存；測試使用隨機/明示假的機密字串。
- 從公司 Host 對唯一已知隔離靶場唯讀 GET：`http://10.56.66.119:18080/lab/healthz` 連線拒絕；`http://10.56.64.121:8001/health` 5 秒逾時。沒有發送 Action、Reset 或其他靶場請求。故 `E2E_SMOKE=NOT_RUN`、Target/Worker root cause `UNKNOWN`，不得改用公司正式目標。

## Report 與正式實驗

- 頂層 `mitre_mapping` 舊路徑只匯集 DecisionScore；本輪加入嚴格 allowlist，從已持久化 L2/L3 NormalizedResult 保留 `normalized_result_id`、`tool_result_id` 與受控模擬分類。L4–L7 類比不冒充已驗證 ATT&CK 執行，不產生新 CVE。只有本機報告測試 PASS；歷史 C Run 不追溯補資料。
- A=D7 紅藍、B=D1 弱掃、C=D3 受控滲透測試。工作草案 `formal-scenario-protocol-v2.draft.md` 給出具體情境候選、Run/Proposal/Execution/Target event/Alert 分母、Reset/STOP/排除與安全中止；它是 `NOT_FROZEN`。原 `formal-experiment-plan-v1.json` 的 L1 ceiling/舊 C 設計不能啟動新版正式實驗。Canonical 提議的每組 3 先導＋30 正式、最多 10 輪仍待研究者核准。正式樣本 A/B/C = `0/0/0`。
- A 必須先有公司隔離靶場下的固定合成 Action/Worker 版本、逐項人工 Approval、完整 Live Trace、獨立藍隊 Alert、Reset/Cleanup；B 須固定弱點/正常配置真值與核准掃描能力；C 須固定 L2/L3 真值與授權範圍。三組均須先通過工程 E2E Smoke，再凍結 Protocol/版本/統計；本輪未開始正式採樣。

## 最小後續順序

1. 在合法隔離環境恢復並唯讀確認原 Target/Worker 健康，核定公司端可用的合成 Target Identity/Scope；不切換到公司正式設備。
2. 審查本次選擇性整合及較新 policy hardening 差異，按固定 Action 逐項完成隔離工程 E2E、Reset、獨立藍隊 Alert 與報告來源核對。L4–L7 Live Action 另需具體人工 Approval。
3. 研究者核准/修訂 `formal-scenario-protocol-v2.draft.md` 的任務真值、樣本/輪數、排除/停止/統計、版本與環境；產生可驗 SHA 的新版凍結 Protocol。
4. 通過前述門檻後才執行先導，再按核定規則執行正式 A/B/C；先導、失敗、工程序列不得混入正式分母。

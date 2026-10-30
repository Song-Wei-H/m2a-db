# GADE／M2A 家用電腦開發交接

本 Repository `Song-Wei-H/m2a-db` 是 **public**。此分支包含可攜式程式、Frozen Protocol v3、已核准的 Scenario B 固定模板 Bundle、合成靶場程式與測試；不應放入公司網路位址、私有 Compose／Nginx／Target Truth 設定、憑證或原始實驗 Evidence。

## 取得來源

首次 Clone：

```powershell
git clone --branch integration/gade-abc-20261027 https://github.com/Song-Wei-H/m2a-db.git
cd m2a-db
```

已有 Clone 時：

```powershell
git fetch origin
git switch integration/gade-abc-20261027
git pull --ff-only origin integration/gade-abc-20261027
```

## 家用合成靶場設定

需求：Windows PowerShell 5.1、Docker Desktop、專案 Python 依賴環境、隔離 PostgreSQL，以及自行建立並隔離的合成網路。Worker／資料庫須使用專用隔離環境；不可連到公司或正式資料庫。Pilot Runtime 的 Codex CLI 版本為 `0.166.0-alpha.5.1`，請先記錄家用端實際版本；Scenario B 使用本 Repository 內固定 Bundle 與 SHA-256 Manifest。

1. 複製 `.env.gade-a-d7.example` 作為欄位說明；該檔中的 TEST-NET 位址只是文件範例，不能作為執行設定。
2. 在本機隔離靶場選擇實際 IP、未衝突的 ingress subnet、image tag 及 Compose project。為 Target、Blue Observer、分離元件各自建立所需的私有 env 檔；填入本機產生的合成測試設定與金鑰，不使用公司憑證。
3. 在同一個 PowerShell 工作階段 dot-source 初始化腳本。參數必須改成家用電腦實際值；腳本會拒絕文件保留位址、未配置於本機的 Host IP、缺少的 env 檔及覆寫既有本機設定。
4. 若要讓 Runner 將核准的收尾摘要寫入該電腦的 Canonical Vault，先設定 `$env:GADE_OBSIDIAN_VAULT` 為家用 Vault 根目錄。Runner 不再含公司使用者的絕對 Vault 路徑。

```powershell
. .\scripts\Initialize-GadeHomeLab.ps1 `
  -TargetHost '<家用主機實際隔離 IPv4>' `
  -WorkerHost '<家用 Worker 實際隔離 IPv4>' `
  -IngressSubnet '<不衝突的隔離 subnet/prefix>' `
  -IngressGateway '<該 subnet 內的 gateway IPv4>' `
  -ImageName 'gade-a-d7-home:<本機固定 tag>' `
  -TargetEnvFile '.\lab\mode-b-target\.env.target.local' `
  -BlueEnvFile '.\lab\mode-b-target\.env.blue.local' `
  -ComponentEnvFile '.\lab\mode-b-target\.env.component.local'
```

產生的 `compose.gade-a-d7.yml`、`nginx.gade-a-d7.conf`、`nuclei-target-truth-v1.json` 與 `.env.*.local` 僅供本機使用且由 `.gitignore` 排除。首次啟動前，人工檢查渲染結果、Compose project、Docker networks、Host-only port binding、Target Scope、Worker Scope、Reset 設定及模板 SHA。只使用隔離合成 Target；不要連公司正式網路或正式資料庫。

`Initialize-GadeHomeLab.ps1` 只產生本機設定與當前 PowerShell 環境變數，不建立容器、不建立金鑰，也不啟動 Pilot。各機的私有設定須經安全管道另行建立；不可將秘密貼入 GitHub、命令列記錄或 Evidence。

## 不在 GitHub 的私有資料

請從可信管道自行建立／安全配置，切勿把這些檔案加進 Repository：

- Target Reset／HMAC 金鑰及 Target 私有 env。
- Blue Observer、分離節點與 Receiver 的私有 env／金鑰。
- `.env.l2.local` 或任何合成帳號秘密。
- PostgreSQL 連線字串、正式或隔離資料庫 dump、密碼及雲端 Token。
- SSH 私鑰、密碼、known-host 私有管理設定。
- 公司原始 Compose、Gateway/Nginx ACL、Target Truth、公司 IP／子網／Worker 位址。
- `local-only`、Pilot Run、原始 Worker／Target/Blue Evidence、診斷輸出及含個資或內部資料的報告。

`.gitignore` 已排除生成的公司／本機設定檔名；公開提交前仍須檢查 staged diff 和 Secret Scan。

## 來源與研究狀態

- Frozen Protocol v3：`experiments/gade-seven-level-v1/formal-scenario-protocol-v3-frozen-20261029.md`，SHA-256 `2f91aefd3276f22cfba60e1321720ab9f2bf319579372b48837213b8d836723d`。
- 公司端 Runtime Source SHA（歷史執行快照識別）：`e4a953f5e81ccee899888cf257d5d2c48365a2e9f84b4a77b74a930e0ad26de5`。它不是本次家用交接 Commit 的來源 SHA。
- 公司端請求模型別名：`gpt-5.6-sol`；實際上游模型身分仍為 `UNKNOWN`。
- 公司端 Pilot：A 3/3、B 3/3、C 1/3；C2 Run `beaf8068e7a4` 因 CLI 安全政策攔截而 FAIL，原始結果保留；C3 尚未執行。
- Formal 樣本：A/B/C = 0/0/0。
- `.165` Runtime 的 A Pilot 3/3 保持其歷史合格狀態；不由本次交接重新分類。
- 實際上游模型身分：`UNKNOWN`。

本次交接中的程式參數化與可攜範本會形成新的 Git 來源版本，不能宣稱與公司 Runtime Source SHA 相同。Protocol v3 要求 Pilot／Formal 的來源快照一致；因此家用端可先完成環境建置、來源審查與快照凍結，**不可將家用 Run 併入公司端既有 Pilot 或 Formal 分母**。接續 C3 前，須確認此新來源快照符合既有 Protocol 的來源一致性條件；若版本不同，先依研究治理決定是否建立同一新 Runtime 下的完整 Pilot 集合。原始 C2 Evidence 不在公開 Repository，請從公司端的安全保存位置讀取；不要重寫或覆蓋公司歷史 Evidence。

## 交接後建議順序

1. Pull 後檢查 Commit、Protocol sidecar SHA、Scenario B Manifest 與模板 SHA。
2. 檢查 Python／PowerShell 版本與依賴來源；設定獨立 Python venv 與隔離 PostgreSQL，不安裝未核准依賴。
3. 建立本機私有靶場設定並審查渲染後 Compose／ACL／Truth；確認 Docker 隔離與 Reset。
4. 凍結家用來源、Runtime、Worker、Target、Policy、DB 與模型可驗證資訊，完成 Pilot 相容性判定後才繼續研究 Run。
5. 每個 Run 保留其真實狀態及 Evidence；上游模型身分若未可核實，一律記為 `UNKNOWN`。

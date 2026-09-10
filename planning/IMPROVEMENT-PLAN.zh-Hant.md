# Sift 改善計畫

日期：2026-09-05。檢視版本：`84ce40d6db9b067a27feffeb81695dff1dece741`（main）。

實作進度：第一輪已落實 P0 核心修正，驗證與後續範圍見 [實作紀錄](./IMPLEMENTATION-STATUS.zh-Hant.md)。下方現況表保留初始觀察，作為修正前基線。

## 1. 產品方向

將 Sift 定位為 **AI coding 工作流中，能說明證據、只攔截可信新增問題的 CLI／PR 檢查工具**。

核心體驗：安裝 → 確認環境 → 掃描變更 → 看懂證據 → 產生修補 → 驗證修補。主要使用者先鎖定個人開發者與小型工程團隊。這是本計畫的產品假設，尚未做使用者訪談。

成功標準是開發者願意保留 CI gate、能判斷掃描是否完整、能重現 finding。先完成可靠掃描與 PR 工作流；Web dashboard、帳號／多租戶、更多模型供應商與自動合併不列入 v0.2。

## 2. 現況與驗證

既有 [v0.2 設計](https://github.com/KJyang-0114/sift/blob/84ce40d6db9b067a27feffeb81695dff1dece741/docs/superpowers/specs/2026-08-16-sift-v0.2-hardening-design.md) 已提出 A1–A6、B7–B10。main 已有 CI、Finding v2、typed diagnostics、context-aware analyzer 與 worker pool；本計畫接續这些成果，不重建核心 schema。

本機為 macOS arm64、Go 1.25.5。以下皆通過：

```sh
go test ./... -count=1 -cover
go test -race ./... -count=1
go vet ./...
go build -o /tmp/sift-plan-20260905-bin ./cmd/sift
```

覆蓋率：core 88.9%、securepath 86.4%、cache 90.9%、scan 40.2%、agent 28.0%、static 19.9%、report 19.6%；CLI、LLM、sandbox 無測試。這些是套件 statement coverage，不能代表真實掃描準確度或安全隔離能力。

### 已驗證問題

CLI 使用本機 fake Semgrep、無依賴暫存專案、offline LLM；registry 使用 fake HTTP transport。未呼叫雲端模型、未執行模型生成程式碼。

| 問題 | 證據 | 使用者影響 |
|---|---|---|
| Analyzer 失敗仍成功退出 | fake Semgrep exit 2；JSON 有 error diagnostic；Sift exit 0 | CI 可能將不完整掃描當成功 |
| Semgrep 結構化 errors 未保留 | 回傳 `results: []` 與 `errors`；報告 diagnostics 為空、exit 0 | 掃描器錯誤消失 |
| 尚無 finding gate | fake critical finding 出現在 JSON，exit 0 | 需新增明確 policy threshold；不能僅靠現有退出碼阻擋 PR |
| 空 diff 沒有機器可讀報告 | clean Git repo 執行 `scan --diff=HEAD --format json`；stdout 為空 | JSON／SARIF 消費端失敗 |
| `--config` 未接入載入流程 | 指定不存在的檔案仍掃描成功 | 團隊以為 policy 已套用，實際使用預設／全域設定 |
| npm HTTP 狀態分類錯誤 | 401、429、500 均產生 1 finding、0 diagnostic | 權限／限流／服務異常被當成不存在套件 |
| 主掃描未使用增量快取 | 多次 CLI 掃描後 cache 為 `{}`；主流程未呼叫 `ScanWithCache` | README 的跳過未變更檔案承諾未落實 |

原始輸出：[CLI evidence](./baseline-evidence.json)、[registry probe](./registry-probe.txt)。Probe 測試通過只代表完成觀察，不代表被觀察行為正確。

### 原始碼確認的後續缺口

- `internal/cmd/root.go` 宣告 `--config`、`--quiet`、`--verbose`，未見對應資料流完整接入。`config.Load()` 只讀全域設定與環境變數；README 所述 `.sift.toml` 尚未接入。
- `internal/scan/orchestrator.go` 的 diff 使用換行分割，失敗時退回全掃；cache／store 以當前工作目錄 `.` 初始化，未綁定 target root。
- `internal/config/config.go` 尚無既有設計要求的 privacy／execution policy；配置 provider + key 會註冊 semantic analyzer 與 test generator。
- `internal/agent/tester.go` 會將生成測試交給 `internal/sandbox/orbital.go`；後者實際直接啟動主機 Python／Node／Go／Bash。暫存目錄不是容器隔離。
- `internal/static/semgrep.go` 缺少 Semgrep 時自動執行 pip／brew 安裝；不適合不可互動、要求可重現的 CI。
- 19 個 YAML 檔共 36 個規則宣告，未見每條規則的正／反例 fixture；尚未實跑規則準確度評測。
- `fix` 顯示 `sift fix --rollback` 提示，但 CLI 未提供該 flag；修補後未自動完成重掃／測試驗證。
- 有 `.goreleaser.yaml`，現有 `.github/workflows` 未見 tag release workflow；installer 未驗證 checksums，取不到最新版本時直接退回 v0.1.0。
- README 各語系功能敘述不一致；中文宣稱的隔離執行、專案設定與目前實作有差距。

範圍限制：這是產品／工程規劃與功能驗證，並非完整漏洞審計。未驗證真實 Semgrep 檢出率、雲端模型、容器 backend、線上 release 安裝或其他 OS 執行。全域規則指定的 `precedent-auth.md`、`routing.md` 檔案存在，但讀取重試逾時，未能取得內容。

## 3. 執行順序

估算以一位熟悉 Go 的開發者全職投入為前提，含測試與文件，未含等待 review 與使用者試用的時間。共約 **25–37 工程日，5–8 週**。以下優先級與工期為規劃估算。

| 階段 | 對應既有計畫 | 工期 | 交付結果 |
|---|---|---:|---|
| P0：結果與退出碼可信 | A2 後續、B8 局部前移 | 3–4 日 | 掃描錯誤可見、HTTP 狀態正確、固定輸出契約 |
| P1：範圍與執行政策落地 | A3–A5 | 8–12 日 | 共用 resolver、設定生效、上傳與執行明確控制 |
| P2：低噪音 PR gate | A6、B7–B8 | 7–10 日 | 規則 fixture、baseline、可信 gate、可重現 alpha |
| P3：增量與修復閉環 | B9–B10，加修復驗證 | 7–11 日 | 正確快取、LLM 評測、修復驗證、v0.2 候選版 |

### P0 — 先修掃描結果契約

拆成兩個可獨立驗收的 PR：

**PR 01：退出碼與報告完整性。** 修改 `internal/cmd/scan.go`、`cmd/sift/main.go`、`internal/scan/orchestrator.go`、`internal/static/semgrep.go`、`internal/report/*`。

- application service 回傳 findings、diagnostics 與 scan completion 狀態；CLI 負責退出碼，移除 command handler 內直接 `os.Exit`。
- 採用既有設計：0 完成且未觸發 gate、1 finding threshold、2 config／target 錯誤、3 partial scan、4 internal failure。
- 定義優先序：fatal config／target 或 internal failure 停止；可保存部分結果的 scan failure 回傳 3，優先於 finding gate 的 1。
- 完整傳遞 Semgrep `errors`、stderr 摘要與 exit status；stdout 僅放指定報告格式。
- 空 diff 仍輸出有效報告與零項 findings；renderer 的寫入錯誤回傳給呼叫者。
- 在門檻尚未實作前，文件明示 finding 不會自動 gate；門檻在 PR 06 啟用。

驗收：原有測試加上 CLI subprocess 測試；本次 evidence 的 analyzer failure／errors array／空 diff 案例全部修正。JSON 可解碼，SARIF 可依 schema 驗證。

**PR 02：registry 語意。** 修改 `internal/agent/package_verify.go` 與測試。

- 引入 exists／missing／unknown 狀態，分開處理 transport error 與 HTTP response。
- npm／PyPI／Go 的 401、403、429、5xx 為 diagnostics；確認的公開 registry 404 才能支持 missing，私有來源不可直接推論幻覺。
- 依個別 registry 定義成功回應、404、redirect、body parsing；加入 bounded retry、timeout、Retry-After 與取消測試。
- 避免「不存在＝critical、惡意」的直接推論；嚴重度依證據與 policy 評定。

驗收：fake HTTP status matrix；401／429／500 不產生 package finding；200、404、無效 body 與取消均有明確結果。

### P1 — 統一路徑、設定與隔離

**PR 03：TargetResolver 與 configuration pipeline。** 新增 resolver／policy 模組，接入 scan 與 fix。

- repository root 只解析一次；輸出共同檔案清單，所有 analyzer 使用同一份範圍。
- Git diff 用 `-z`，處理 rename／delete／空白／Unicode／換行檔名、子目錄、未追蹤檔案與 merge-base。差異模式明確命名與文件化。
- diff ref 錯誤回報 target error，禁止默默擴成全掃。
- symlink containment、ignore、檔案大小／數量限制統一處理；保留現有 securepath 行為測試。
- 設定優先序明定為 defaults → global → project → explicit config → env → flags。明確指定但不存在或含未知欄位的設定應報錯。
- `--quiet`、`--verbose`、format validation 接通；state 綁定掃描 root，跨 cwd 使用結果一致。

驗收：暫存 Git repository table tests；同一 target 在不同 cwd／不同輸出格式下，掃描範圍一致；所有宣告 flags 都有行為測試。

**PR 04：Privacy 與 execution policy。** 接續既有 A4 設計。

- provider 預設 offline；雲端 source upload 必須經明確 acknowledgement；`--no-upload` 優先。
- 區分「不傳雲端原始碼」與「完全不連網」；後者同時停用 registry lookup、自動安裝與雲端 LLM。報告標註被 policy 停用的 analyzer。
- key 保持 env-first；保留現有 0600 設定保護，補舊檔、diagnostics、history 與 evidence 的遮罩測試。
- test generation 與 execution 分離，預設只生成。先移除主機自動執行入口，再接容器 backend。
- 區分本機 Ollama 與雲端 provider 的 key／upload policy，避免一律以 API key 判斷可用性。

驗收：有 key 但未允許 upload 時，fake LLM 呼叫數為 0；未允許 execution 時，executor 呼叫數為 0；完全 offline 不產生任何外連。

**PR 05：Runner、container executor 與 doctor。** 接續 A5。

- 注入 `CommandRunner`、`Executor`；使用 context、argument array、輸出上限與終止清理。
- Linux／macOS 使用 Docker 或 Podman；network off、non-root、read-only rootfs、CPU／memory／PID／timeout 限制。
- 只複製必要 source 與 generated test；測試工作目錄能 import 受測模組；缺 pytest／import error 應列 environment diagnostic。
- Windows 與無 backend 環境只生成測試。
- 新增 `sift doctor`，說明 Semgrep、provider、container 與有效 policy；scan 缺工具時回報診斷，安裝移到明確 setup 動作。

驗收：fake runner contract tests；可用 backend 的 Linux／macOS integration tests；取消會回收子程序／容器；不洩漏主機環境變數。

### P2 — 能長期留在 PR 的檢查工具

**PR 06：規則品質、baseline 與 gate。** 接續 B7／B8。

- 每條 Semgrep 規則加入 positive、negative 與正常 framework 寫法；目前 36 條至少 72 個基本案例，另加邊界案例。
- 檢視 ERROR→critical 的全域映射；rule severity 與 confidence 應各自校準。
- 先將 JS／TS、Python 作為主要準確度驗收集合；其他已支援語言保留功能與 smoke tests，尚未評測的能力標明狀態。
- dependency parser 支援 npm workspace／file／git／alias／private scope，Python extras／markers，Cargo rename／path／workspace，Go replace／private module；分批依 fixture 補齐。
- suppression 與 baseline 保留原因與審計資訊；fingerprint 跨 root 穩定，對單純插入無關程式行盡量穩定。
- 同 analyzer 依 fingerprint 去重；跨 analyzer 使用明確的 rule-family／位置對應，保留來源，不假設目前含 source namespace 的 fingerprint 會自動合併。
- 新增明確 `--fail-on`、`--min-confidence`、`--baseline`；只對新增且符合證據／可信度條件的 finding gate。LLM-only 預設 advisory。

驗收：所有發佈規則通過正反例；既有 baseline 不阻擋、新增 high-confidence finding 阻擋；suppression 不刪除審計記錄。公開每條規則與整體 confusion matrix，避免只報一個總分。

**PR 07：CI、release 與文件。** 完成 A6，發布 `v0.2.0-alpha.1` 的候選產物。

- 同一次掃描生成 SARIF 並保存退出碼；即使 findings 觸發 gate 或 partial scan，也先上傳有效報告，最後再還原 gate 結果。不要為 terminal／SARIF 掃描兩次。
- 固定 Semgrep／toolchain 版本；CI 不需 API key；加入 rule tests、CLI tests、SARIF validation。
- 接上 tag release workflow、跨平台 build／安裝 smoke tests、checksum 驗證、可指定版本與 user-local install。
- installer 查不到 release 時清楚失敗，取消偷偷降版；安裝失敗可保留原 binary。
- README 三語同步：真實支援矩陣、offline 語意、exit codes、首次掃描、GitHub Actions 範例、已知限制與 MIGRATION。

驗收：全新測試環境可依文件完成安裝與無 key 掃描；實際 GitHub PR 顯示 SARIF；安裝錯誤與 gate 都可重現。

### P3 — 增量、LLM 與修復驗證

**PR 08：把 cache 接入主流程。** 接續 B10。

- 儲存可重用完整 analyzer result，不能只記 finding 數量；cache hit 仍需重現原 findings。
- key 包含內容、resolver／policy、rule bundle、analyzer 版本；LLM 包含 provider、model、prompt version。Registry 加 TTL／registry identity，不能把暫時 unknown 當成功缓存。
- analyzer timeout／失敗不寫 successful cache；相關設定、共享程式碼與 manifest 變更有保守失效策略。
- 原子寫入、同時掃描、SQLite close／error handling、retention policy 納入測試。

驗收：冷／熱掃描 findings 一致；改規則、policy、model、依賴或必要上下文時確實失效。先測量，再設定效能承諾；固定 1,000／10,000 檔 fixture，追蹤 p50、p95、RSS、hit rate。

**PR 09：LLM 評測與可驗證修補。** 接續 B9，补齊 fix 工作流。

- LLM adapter 加 HTTP contract tests、structured output validation、bounded retry／response、cancel 與 cost budget。
- 建立至少 100 個人工標記樣本，含正常程式、真實缺陷、多檔上下文與不可信來源文字；分 development／holdout，不用調 prompt 的資料宣稱泛化效果。
- 輸出 model／prompt version、precision、recall、false-positive rate、latency、token／費用估算；尚未量測前不宣稱準確率。
- fix 先輸出完整 diff；套用前驗證原始內容 hash，保護使用者未提交變更；同檔修補需衝突處理。
- 套用後執行政策允許的檢查／測試／重掃；測試執行受同一 executor policy 約束。區分 generated／applied／verified 狀態。
- 接通既有 rollback 能力至 CLI，記錄每次修補 manifest；rollback 同樣檢查檔案是否已被使用者再次修改。

驗收：fake LLM failure matrix 通過；不合法路徑／過期 patch 不套用；測試失敗不標示 verified；rollback 恢復本次修改且不覆盖後續修改。

## 4. 發版門檻與追蹤指標

- **完整性：** 每次掃描都有完成／部分完成／政策停用狀態；error 不再偽裝成 clean scan。
- **準確度：** 100% 發佈規則有正反例；blocking findings 的人工標記 holdout precision 目標 ≥95%，須一起報樣本數／信賴區間與 recall。此為目標，非現況。
- **一致性：** cold／warm／diff 的預期 finding 集合以 fixture 驗證；格式差異不改變掃描結果。
- **可用性：** 邀請 3–5 位開發者，在 5 個代表專案試用兩週；記錄首次成功掃描時間、每 PR 新 findings 數、誤報原因、gate 是否被關閉。不預設加入遥測。
- **修復品質：** 分開記錄修補生成率、套用率、驗證通過率與回滾率，避免把 patch 生成成功當修好。

v0.2.0 需完成 P0–P3 必要驗收，並將尚未成熟的 execution／auto-fix 能力標 experimental；不能以總 coverage 或測試全綠代替工作流驗收。

## 5. 第一個工作包

直接從 PR 01 開始：固定 scan result／exit-code 契約，補 CLI 行為測試，修 Semgrep errors 與空 diff 報告。約 2–3 日；接著 PR 02 修 registry 語意。

保留既有設計的 PR 治理：每個 PR 能獨立 build／test，附風險、相容性與回退说明；相依 PR 經 maintainer review 後再推進。此階段只交付規劃與證據，未修改 upstream、建立 issue、提交 PR 或發布 release。

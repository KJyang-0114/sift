# 第一輪實作紀錄：P0 掃描可靠性

日期：2026-09-05。基底：`84ce40d6db9b067a27feffeb81695dff1dece741`。
本機分支：`codex/scan-result-reliability`。變更保留在工作目錄，尚未 commit／push／建立 PR。

## 已完成

- [x] 引入 `core.ScanResult` 與 typed operational error；掃描資料收集與報告輸出分離。
- [x] CLI 退出碼：0 完成、2 設定／參數／目標錯誤、3 部分失敗、4 內部／輸出錯誤。1 保留給後續 finding gate。
- [x] 部分失敗保留 findings；JSON `status`、SARIF `executionSuccessful`、terminal／LLM diagnostics 表達一致。
- [x] Semgrep errors array、非零退出碼、stderr 摘要、timeout、輸出上限與不合法 JSON 不再被忽略。
- [x] 空 diff 輸出有效空報告；失效 ref 不再擴成全掃。Git 使用 NUL 分隔，保留所選檔案／子目錄範圍，排除已刪除與未追蹤檔案。
- [x] `--config` 接入 scan／fix／config；scan 驗證 format、timeout、concurrency、sandbox；quiet／verbose 生效。
- [x] 狀態檔綁定 target root，SQLite 連線在掃描後關閉，儲存失敗有 diagnostics。
- [x] Registry 分離 exists／missing／unknown；HTTP 401／403／429／5xx 不再產生不存在套件 finding。
- [x] Registry 最多兩次重試，受取消與 Retry-After 限制；Cargo response 限制大小並驗證內容。
- [x] Scoped npm 與 Go 的公開 not-found 以 unknown 處理；公開缺失套件改為 medium advisory，不宣稱惡意。
- [x] Go require 區塊與 proxy 大寫路徑編碼；未知 provider 初始化失敗不再靜默省略 analyzer。
- [x] 已配置 LLM 的 request／parse error 與空測試生成回應標為分析失敗。
- [x] scan 不再自動執行 pip／brew 安裝 Semgrep。
- [x] CI 改為一次 SARIF 掃描，先上傳有效報告，再還原退出碼。
- [x] 三語 README 與 MIGRATION 更新，修正未完成快取／專案設定／容器隔離的能力敘述。

## 驗證結果

以下命令通過：

```sh
make ci
go test -race ./... -count=1
go mod verify
git diff --check
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/sift-linux-amd64 ./cmd/sift
env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/sift-windows-amd64.exe ./cmd/sift
```

本機 `make ci` 包含 formatting、vet、單元／整合測試與 macOS arm64 build；交叉編譯不代表 Linux／Windows 執行驗收。

- 真實 CLI binary + fake Semgrep subprocess：17 個案例通過，涵蓋部分成功、輸出格式、空 diff、timeout、輸出上限、參數錯誤與錯誤退出碼。
- Fake registry transport：HTTP status matrix、限流重試、取消、Cargo malformed／oversized body、scoped/private ambiguity、Go proxy case encoding。
- Fake LLM：request failure／empty test code 不會啟動生成程式碼執行，結果為 partial。
- 官方報告格式所指向的 SARIF 2.1.0 JSON Schema：complete、finding、partial、errors 四份報告通過 Draft 7 + format checks。
- GitHub Actions scan shell step 在本機驗證：complete 留下 exit 0，partial 留下有效 SARIF 與 exit 3；尚未執行 GitHub upload。

原始驗證資料：[verification/results.json](./verification/results.json)。報告樣本位於同目錄；使用 fixture findings，不是真實漏洞結論。

## 使用與相容性

本機 binary 已建立於專案根目錄 `sift`。

```sh
./sift scan --help
./sift scan . --config path/to/config.toml --format json
```

實際 static scan 需事先安裝 Semgrep。Registry verification 仍會連網；provider offline 只代表不使用 LLM。完整遷移與回退說明見 [MIGRATION.md](../MIGRATION.md)。

本輪没有啟用 findings gate，因此出現 critical finding 本身仍不會令 CLI 失敗；需要以報告檢查 findings，等待 P2 policy 完成。

## 尚待後續階段

- P1：完整 resolver／symlink containment、project config layering、來源上傳 consent、生成與執行分離、container executor。
- P2：所有規則正反例、dependency parser 完整語意、baseline／suppression／可信新增 finding gate、可重現 release。
- P3：完整 findings cache、LLM 評測、修補後驗證與 rollback CLI。

本輪部分前移了 config 與 Git 行為修正，但不代表 P1 已完成。未使用雲端模型、未實跑容器隔離、未測量真實 Semgrep 準確度。

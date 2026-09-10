# Sift v1.5

Go CLI，用靜態規則、套件驗證與選擇性 LLM 分析檢查程式碼，並輸出 terminal、JSON、SARIF 或 LLM-readable report。

[繁體中文](./README.zh-Hant.md) · [日本語](./README.ja.md)

![Sift architecture](assets/architecture.png)

## 掃描流程

```text
CLI target / config / diff ref
  → Semgrep rules
  → Package verifier
  → Optional semantic analyzer
  → Concurrent orchestration
  → Terminal / JSON / SARIF / LLM report
  → SQLite scan history
```

## 主要功能

- 掃描目錄、單一檔案或 Git diff。
- 執行 Semgrep 與 dependency package verification。
- 在設定 provider 後加入 semantic analysis 與 test generation。
- 以 worker pool 控制 concurrency 與 timeout。
- 提供 SHA-256 cache 元件；主掃描流程的增量快取仍待接入。
- 將掃描紀錄與 findings 寫入 SQLite。

## 核心程式

| Analyzer composition | Parallel execution |
|---|---|
| ![Analyzer composition](assets/orchestrator-code.png) | ![Parallel analyzers](assets/concurrency-code.png) |

## 實作重點

### Deterministic first

已知 vulnerability class 先交給可重現的 rules。LLM analyzer 用於補充語意判斷，不取代靜態檢查。

### 無 LLM 模式

provider = "offline" 時不呼叫 LLM；套件驗證仍會連線 registry。Ollama 不需要 API key。

### Output formats

Terminal 適合本機閱讀，JSON 適合 automation，SARIF 可接 GitHub Code Scanning，LLM format 可交給後續修復流程。

### Concurrent execution

Analyzer 以 goroutine 並行，結果依原始 index 回填。Worker pool 控制同時執行數量與 timeout。

## 使用方式

```bash
pip install semgrep
go build -o sift ./cmd/sift
./sift init
./sift scan .
./sift scan --diff=HEAD~1 --format sarif
```

掃描不再自動安裝 Semgrep。`--config FILE` 可指定設定檔；缺檔會報錯。
`--diff` 掃描已追蹤的變更，排除刪除與未追蹤檔案；沒有變更仍輸出有效報告。

| 退出碼 | 意義 |
|---|---|
| `0` | 啟用的分析已完成；findings 目前僅供參考 |
| `2` | 設定、參數、目標或 diff ref 無效 |
| `3` | 部分掃描失敗；報告保留已完成的結果與 diagnostics |
| `4` | 內部或報告寫入失敗 |

JSON 包含 `status: complete / partial`；SARIF 使用 `executionSuccessful`。
registry 限流、權限與服務異常列為 diagnostics，不會當成不存在套件。
CI 應先保存、上傳報告，再回傳掃描退出碼。完整變更見 [MIGRATION.md](MIGRATION.md)。

## 驗證

```bash
go test ./...
go build ./cmd/sift
```

## 限制

- 靜態規則與模型判斷都可能產生 false positive。
- LLM 分析需要自行提供 provider key。
- 部分 packages 尚未加入行為測試。
- 掃描結果仍需人工確認 data flow 與實際執行路徑。

## License

詳見 [LICENSE](LICENSE)。

## v1.5 使用與復原

從 GitHub Releases 下載對應平台壓縮檔，核對 `checksums.txt`，解壓後執行 `sift --version`。
Semgrep 需另行安裝；規則已嵌入 binary。

```bash
sift fix . --dry-run
sift fix path/to/file.py --interactive
sift fix path/to/file.py --rollback
```

`--auto`、`--interactive`、`--dry-run`、`--rollback` 互斥。套用 patch 前建立 `.sift.bak`；已有備份時停止，不覆蓋原始版本。套用成功不代表通過測試。

需要生成 Python 測試時，在設定加入：

```toml
[execution]
generate = true
enabled = false
```

測試保存在 `.sift/generated-tests/`，由你確認 imports、測試假設後手動執行。預設不生成，也不自動執行模型程式碼。Container executor 尚未提供；設為 `enabled = true` 會回報 partial，不會退回主機執行。

版本變更見 [CHANGELOG.md](CHANGELOG.md)。

維護者可使用 `python3 scripts/build-release.py --version 1.5.0` 重建六個平台壓縮檔與 SHA-256 清單；輸出位於 `dist/1.5.0/`，腳本不會發布遠端 release。

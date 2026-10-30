# 在任何 CI 使用 Sift

Sift 是單一 binary，輸出 JSON／SARIF，因此不綁定特定平台。最簡單的方式是使用內含鎖版 Semgrep 的 Docker image。

## GitHub Actions

```yaml
name: sift
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: KJyang-0114/sift@v1
```

Action 會安裝鎖版的 Semgrep 與 Sift、執行一次掃描、上傳 SARIF 到 Code Scanning、在 Actions 頁面寫入摘要，最後才回傳 gate 結果。支援 Linux 與 macOS runner。

| Input | 預設 | 說明 |
|---|---|---|
| `path` | `.` | 掃描目標 |
| `fail-on` | `high` | 達到此嚴重度的新問題會讓 job 失敗；`none` 只報告 |
| `min-confidence` | `medium` | 計入 gate 的最低信心度 |
| `baseline` | `sift-baseline.json` | 檔案存在時才使用 |
| `upload-sarif` | `true` | 上傳到 Code Scanning（需要 `security-events: write`） |
| `category` | `sift` | Code Scanning 分類 |
| `vulnerabilities` | `true` | 是否查詢 OSV.dev |
| `version` | `latest` | 例如 `v1.6.0`；`source` 會從 Action 的原始碼建置 |
| `args` | | 附加在 `sift scan` 後的參數 |

Outputs：`exit-code`、`sarif-file`、`findings`（新問題數）。要啟用 LLM 分析，在 job 設定 `SIFT_LLM_PROVIDER` 與 `SIFT_LLM_API_KEY`（用 secrets）。

## Docker（任何支援容器的 CI）

```bash
docker run --rm -v "$PWD:/src" ghcr.io/kjyang-0114/sift:latest \
  scan . --format sarif --output sift.sarif --fail-on high
```

- Image 內含 `sift`、固定版本的 Semgrep 與 `git`（`--diff` 需要）。
- 以非 root 使用者（uid 10001）執行；報告寫到掛載的 `/src`，主機需允許該使用者寫入，或改寫到 `/tmp` 再複製出來。
- 標籤：`latest`、`vX.Y.Z`。
- 預設會連線 OSV.dev 查詢已知漏洞；`-e SIFT_VULNERABILITIES=false` 只關閉這項查詢。套件存在性檢查仍需連線 npm、PyPI、Go proxy 或 crates.io，無法連線時掃描會是 partial（exit 3）。

## 退出碼

| 碼 | 意義 | CI 建議 |
|---|---|---|
| `0` | 完成，沒有違反 gate | 通過 |
| `1` | 有 finding 違反 `--fail-on` | 失敗；先上傳報告 |
| `2` | 參數／設定／目標錯誤 | 失敗；修正設定 |
| `3` | 部分分析失敗 | 失敗；檢查 diagnostics |
| `4` | 內部錯誤或報告寫入失敗 | 失敗 |

報告一定在回傳退出碼之前寫完，所以 CI 應「先保存或上傳報告，再回傳退出碼」。

## 範本

| 平台 | 範本 |
|---|---|
| GitHub Actions | `uses: KJyang-0114/sift@v1`（見上方） |
| GitLab CI | [`gitlab-ci.yml`](gitlab-ci.yml) |
| 其他（Jenkins、CircleCI、Buildkite、各種 forge 的 CI） | 使用上方的 `docker run` 指令 |

## 舊專案導入

```bash
sift scan . --write-baseline sift-baseline.json   # 接受現有問題
git add sift-baseline.json && git commit -m "Add Sift baseline"
sift scan . --baseline sift-baseline.json --fail-on high   # 之後只擋新增問題
```

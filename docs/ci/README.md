# 在任何 CI 使用 Sift

Sift 是單一 binary，輸出 JSON／SARIF，因此不綁定特定平台。最簡單的方式是使用內含鎖版 Semgrep 的 Docker image。

## Docker（任何支援容器的 CI）

```bash
docker run --rm -v "$PWD:/src" ghcr.io/kjyang-0114/sift:latest \
  scan . --format sarif --output sift.sarif --fail-on high
```

- Image 內含 `sift`、固定版本的 Semgrep 與 `git`（`--diff` 需要）。
- 以非 root 使用者（uid 10001）執行；報告寫到掛載的 `/src`，主機需允許該使用者寫入，或改寫到 `/tmp` 再複製出來。
- 標籤：`latest`、`vX.Y.Z`。
- 預設會連線 OSV.dev 查詢已知漏洞；離線環境加 `-e SIFT_VULNERABILITIES=false`。

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
| GitHub Actions | 參考 [`.github/workflows/sift-scan.yml`](../../.github/workflows/sift-scan.yml)（上傳 SARIF 到 Code Scanning） |
| GitLab CI | [`gitlab-ci.yml`](gitlab-ci.yml) |
| 其他（Jenkins、CircleCI、Buildkite、各種 forge 的 CI） | 使用上方的 `docker run` 指令 |

## 舊專案導入

```bash
sift scan . --write-baseline sift-baseline.json   # 接受現有問題
git add sift-baseline.json && git commit -m "Add Sift baseline"
sift scan . --baseline sift-baseline.json --fail-on high   # 之後只擋新增問題
```

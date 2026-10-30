# 讓 AI coding agent 自己修掉 Sift 找到的問題

Sift 可以放進 agent 的工作迴圈：agent 改完程式 → Sift 掃描 → 有新的高風險問題就把報告交回 agent 修正 → 乾淨後才結束。人只需要審查最後的結果。

前提：已安裝 `sift` 與 `semgrep`（或使用 [Docker image](ci/README.md)）。舊專案建議先建立 baseline，只讓新問題觸發：

```bash
sift scan . --write-baseline sift-baseline.json
git add sift-baseline.json && git commit -m "Add Sift baseline"
```

## Claude Code（Stop hook）

agent 準備結束時，hook 會掃描專案；有未在 baseline 的 high 以上、信心度 medium 以上的問題，就把 `--format llm` 報告交回給 Claude 繼續修正。

1. 複製腳本：

   ```bash
   mkdir -p .claude/hooks
   curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/integrations/claude-code/sift-stop-hook.sh \
     -o .claude/hooks/sift-stop-hook.sh
   chmod +x .claude/hooks/sift-stop-hook.sh
   ```

2. 在 `.claude/settings.json` 註冊（範例：[settings.example.json](../integrations/claude-code/settings.example.json)）：

   ```json
   {
     "hooks": {
       "Stop": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/sift-stop-hook.sh",
               "timeout": 300
             }
           ]
         }
       ]
     }
   }
   ```

行為：

| 狀況 | 結果 |
|---|---|
| 有新問題（Sift exit 1） | 阻止結束，報告成為 Claude 的下一個指示 |
| 沒有新問題 | 正常結束 |
| Claude 已因此 hook 修正過一輪又要結束（`stop_hook_active`） | 不再阻擋，避免無限循環 |
| 掃描不完整（exit 3）、沒有安裝 sift | 不阻擋 |

可用環境變數調整門檻：`SIFT_FAIL_ON`（預設 `high`）、`SIFT_MIN_CONFIDENCE`（預設 `medium`）。

## 其他 agent

任何能執行指令並讀取輸出的 agent 都能用同一個模式：

```bash
sift scan . --format llm --baseline sift-baseline.json --fail-on high --min-confidence medium
```

- 退出碼 `1` 代表有新問題，stdout 是給 LLM 的修正指示（已抑制的問題會註明不要修改）。
- 退出碼 `0` 代表可以結束；`3` 代表掃描不完整，應回報給人而不是讓 agent 反覆重試。

## pre-commit

在專案的 `.pre-commit-config.yaml` 加入（`rev` 請改成實際的 release tag）：

```yaml
repos:
  - repo: https://github.com/KJyang-0114/sift
    rev: vX.Y.Z
    hooks:
      - id: sift          # 由 pre-commit 從原始碼建置 sift（需要 Go）
      # - id: sift-system # 或使用 PATH 上已安裝的 sift
```

預設參數：`scan . --fail-on high --min-confidence medium --quiet`，可用 `args:` 覆寫，例如加上 `--baseline, sift-baseline.json`。Semgrep 需另外安裝。

## 注意

- 掃描會把套件名稱與版本送到 OSV.dev 比對已知漏洞，`SIFT_VULNERABILITIES=false` 可關閉這項查詢。套件存在性檢查仍需連線各 registry；無法連線時掃描為 partial（exit 3），hook 不會因此阻擋 agent。
- agent 的修正仍需人工審查。Sift 只確認「沒有偵測到新問題」，不代表程式碼沒有問題。

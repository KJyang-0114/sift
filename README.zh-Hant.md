# Sift

> AI 全自動程式碼安全掃描工具 — 開源、自帶 API Key、一行指令安裝。

*[English](./README.md) | [日本語](./README.ja.md)*

Sift 是 Vibecoding 時代的守門員。它結合 Semgrep 靜態規則與 LLM 語意分析，掃描 AI 產出程式碼的安全漏洞、幻覺套件、以及邏輯錯誤。

## 快速開始

先安裝 Semgrep（例如於 Python 環境執行 `pip install semgrep`）。Sift 掃描不會自動安裝外部工具。

```bash
# 1. 安裝
curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | bash

# 2. 設定（最多三題）
sift init

# 3. 掃描
sift scan .
```

## 安裝方式

### 自動安裝（推薦）

```bash
curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | bash
```

### 手動安裝 / AI Agent 安裝

如果你是正在協助使用者安裝 Sift 的 AI 程式碼 Agent，請執行以下指令：

```bash
# 1. 取得最新版本號
SIFT_VERSION=$(curl -s https://api.github.com/repos/KJyang-0114/sift/releases/latest | jq -r .tag_name)

# 2. 偵測作業系統與架構
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

# 3. 下載並安裝
curl -fsSL "https://github.com/KJyang-0114/sift/releases/download/${SIFT_VERSION}/sift_${OS}_${ARCH}.tar.gz" \
  | sudo tar -xz -C /usr/local/bin sift

# 4. 驗證安裝
sift --version
```

### 從原始碼編譯

```bash
git clone https://github.com/KJyang-0114/sift.git
cd sift
go build -o sift ./cmd/sift/
sudo mv sift /usr/local/bin/
```

## 使用方式

### 掃描完整性

`scan` 的退出碼：`0`＝啟用的分析完成、`2`＝參數／設定／目標錯誤、`3`＝部分掃描失敗、`4`＝內部／報告寫入失敗。Findings 目前是 advisory，尚無 finding gate；`1` 保留供後續使用。

JSON 帶有 `status: complete / partial`，SARIF 以 `executionSuccessful` 表達完整性；部分失敗仍保留 findings 與 diagnostics。空 diff 仍輸出有效報告。Registry 的 401／429／5xx 不會變成不存在套件的 finding。

`--config FILE` 指定必須存在的設定檔；`--quiet` 保留 JSON／SARIF／LLM 輸出，`--verbose` 將摘要寫到 stderr。CI 先保存並上傳有效報告，再回傳退出碼。詳見 [遷移文件](MIGRATION.md)。

### 基本掃描

```bash
# 掃描整個專案
sift scan .

# 掃描單一檔案
sift scan src/main.go

# 只掃描變更的檔案（vs HEAD）
sift scan --diff

# 掃描自上次 commit 以來的變更
sift scan --diff=HEAD~1
```

### 輸出格式

```bash
# 終端彩色輸出（預設）
sift scan . --format terminal

# JSON 格式（程式化消費）
sift scan . --format json

# SARIF 格式（GitHub Code Scanning 相容）
sift scan . --format sarif

# LLM 可消費格式（直接貼給 LLM 修復）
sift scan . --format llm
```

`--format llm` 是 Sift 的殺手級功能：輸出可以直接丟給任何 LLM 做自動修復：

```bash
sift scan . --format llm | claude -p "修復以上所有問題"
```

### CI/CD 整合

```yaml
# .github/workflows/sift.yml
name: sift
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - name: Run Sift scan
        env:
          SIFT_LLM_API_KEY: ${{ secrets.SIFT_LLM_API_KEY }}
        run: |
          go install github.com/KJyang-0114/sift/cmd/sift@latest
          sift scan . --format sarif
```

### 環境變數

不想用設定檔？用環境變數即可：

```bash
export SIFT_LLM_PROVIDER=anthropic
export SIFT_LLM_API_KEY=sk-ant-xxx
export SIFT_LLM_MODEL=claude-sonnet-4-6

sift scan .
```

## 功能

- **靜態安全掃描**：SQL Injection、XSS、Command Injection、Hardcoded Secrets
- **幻覺套件檢測**：驗證依賴是否真實存在於 NPM / PyPI / Cargo 註冊表
- **LLM 語意分析**：偵測邏輯錯誤、Prompt Injection 風險
- **自動測試生成**：AST + LLM 雙層推導邊界測試用例
- **實驗性動態執行**：目前 Orbital 使用主機程序與暫存目錄執行生成測試；容器隔離與明確執行政策仍待實作。
- **LLM 直送輸出**：`--format llm` 產出可直接丟給 LLM 修復的報告

## 設定

設定檔位於 `~/.sift/config.toml`，`sift init` 會自動產生。

```toml
[llm]
provider = "anthropic"        # anthropic | openai | openrouter | ollama | siliconflow | gemini | deepseek | offline
api_key = "sk-ant-xxx"        # 或用環境變數 SIFT_LLM_API_KEY
model = "claude-sonnet-4-6"

[scan]
timeout = 120
concurrency = 4
sandbox = "orbital"           # orbital

[output]
format = "terminal"           # terminal | json | sarif | llm
color = true
```

可使用 `sift scan . --config path/to/config.toml` 指定設定檔。專案級 `.sift.toml` 自動載入、`rules.ignore` 與 severity policy 尚未接入。

## 授權

MIT License

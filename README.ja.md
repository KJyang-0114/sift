# Sift

> AI 搭載コードセキュリティスキャナ — オープンソース、API キー持参、ワンラインインストール。

*[English](./README.md) | [中文](./README.zh-Hant.md)*

Sift は Vibecoding 時代のゲートキーパーです。Semgrep の静的ルールと LLM の意味解析を組み合わせ、AI が生成したコードのセキュリティ脆弱性、幻覚パッケージ、ロジックエラーをスキャンします。

## クイックスタート

```bash
# 1. インストール
curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | bash

# 2. 設定（最大3問）
sift init

# 3. スキャン
sift scan .
```

## インストール

### 自動インストール（推奨）

```bash
curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | bash
```

### 手動 / AI エージェント向け

AI コーディングエージェントがユーザーの Sift インストールを支援する場合、以下のコマンドを実行してください：

```bash
# 1. 最新バージョンを取得
SIFT_VERSION=$(curl -s https://api.github.com/repos/KJyang-0114/sift/releases/latest | jq -r .tag_name)

# 2. OS とアーキテクチャを検出
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

# 3. ダウンロードとインストール
curl -fsSL "https://github.com/KJyang-0114/sift/releases/download/${SIFT_VERSION}/sift_${OS}_${ARCH}.tar.gz" \
  | sudo tar -xz -C /usr/local/bin sift

# 4. 確認
sift --version
```

### ソースからビルド

```bash
git clone https://github.com/KJyang-0114/sift.git
cd sift
go build -o sift ./cmd/sift/
sudo mv sift /usr/local/bin/
```

## 使い方

### 基本スキャン

```bash
# プロジェクト全体をスキャン
sift scan .

# 単一ファイルをスキャン
sift scan src/main.go

# 変更されたファイルのみスキャン
sift scan --diff HEAD~1
```

### 出力フォーマット

```bash
# カラー端末出力（デフォルト）
sift scan . --format terminal

# JSON 形式（プログラム用）
sift scan . --format json

# SARIF 形式（GitHub Code Scanning 互換）
sift scan . --format sarif

# LLM 可読形式（任意の LLM に貼り付けて修正可能）
sift scan . --format llm
```

`--format llm` は Sift のキラー機能です — 出力を LLM に直接パイプして自動修正できます：

```bash
sift scan . --format llm | claude -p "上記の全問題を修正してください"
```

### CI/CD 統合

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

### 環境変数

設定ファイルを使いたくない場合は環境変数で：

```bash
export SIFT_LLM_PROVIDER=anthropic
export SIFT_LLM_API_KEY=sk-ant-xxx
export SIFT_LLM_MODEL=claude-sonnet-4-6

sift scan .
```

## 機能

- **静的セキュリティスキャン**：SQL インジェクション、XSS、コマンドインジェクション、ハードコードされたシークレット
- **幻覚パッケージ検出**：依存パッケージが NPM / PyPI / Cargo レジストリに実在するか検証
- **LLM 意味解析**：ロジックエラーとプロンプトインジェクションリスクを検出
- **自動テスト生成**：AST + LLM の二層エッジケーステスト生成
- **サンドボックス動的実行**：隔離環境でのコード実行とランタイムエラー捕捉
- **LLM 直接出力**：`--format llm` で LLM が直接修正できるレポートを生成

## 設定

設定ファイルは `~/.sift/config.toml` にあり、`sift init` で自動生成されます。

```toml
[llm]
provider = "anthropic"        # anthropic | openai | openrouter | ollama | siliconflow | gemini | deepseek | offline
api_key = "sk-ant-xxx"        # または SIFT_LLM_API_KEY 環境変数を使用
model = "claude-sonnet-4-6"

[scan]
timeout = 120
concurrency = 4
sandbox = "orbital"           # orbital | docker | firecracker

[output]
format = "terminal"           # terminal | json | sarif | llm
color = true
```

プロジェクト固有の設定は `.sift.toml` に配置します：

```toml
[rules]
ignore = ["vendor/", "node_modules/", "*.pb.go"]
severity = ["critical", "high", "medium"]
```

## ライセンス

MIT License

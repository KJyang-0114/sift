<h1 align="center">Sift</h1>

<p align="center">
  <strong>AI が書いたコードのためのセキュリティゲート。</strong><br>
  コードと依存関係をスキャンし、CI では<em>新しく</em>入った高リスクの問題だけをブロックし、<br>
  結果をコーディングエージェントに返して修正させます。
</p>

<p align="center">
  <a href="https://github.com/KJyang-0114/sift/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/KJyang-0114/sift/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/KJyang-0114/sift/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/KJyang-0114/sift"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-Hant.md">繁體中文</a> · <strong>日本語</strong>
</p>

<p align="center">
  <img src="assets/terminal-demo.svg" alt="Sift が新しいコマンドインジェクションと脆弱な lodash をブロックし、受け入れ済みの 14 件を非表示にしている" width="820">
</p>

## Sift を使う理由

- **AI がよく犯すミスを検出。** インジェクション、XSS、SSRF、安全でないデシリアライズ、ハードコードされたシークレット、JWT・セッション設定の誤りを 38 個の Semgrep ルールで検出します。
- **最新の CVE を把握。** スキャンのたびに lockfile の正確なバージョンを [OSV.dev](https://osv.dev) で照合します。[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)（実際に悪用が確認された脆弱性）に載っている CVE は critical に引き上げ、悪意あるパッケージや AI が作り出した存在しないパッケージも検出します。
- **初日から導入可能。** baseline で既存の問題を受け入れ、`--fail-on high` は今回の変更で増えた問題だけをブロックします。コードの移動で受け入れ済みの問題が再び出ることはありません。
- **いつもの場所で動く。** ターミナル、GitHub Code Scanning（SARIF）、Docker イメージによる任意の CI、Claude Code・pre-commit フック。
- **鍵は自分で選ぶ。** 静的解析と依存関係チェックに API キーは不要です。LLM 解析は任意で、Anthropic、OpenAI、Gemini、OpenRouter、DeepSeek、SiliconFlow、ローカルの Ollama に対応します。

## 仕組み

<p align="center">
  <img src="assets/how-it-works.svg" alt="コードはルール・依存関係・任意の意味解析を経て、baseline と fail-on ポリシーを通り、ターミナル・SARIF・JSON・エージェントへ出力される" width="100%">
</p>

## クイックスタート

```bash
pip install semgrep
curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | bash
sift scan .
```

| プラットフォーム | インストール |
|---|---|
| macOS / Linux | `curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh \| bash` |
| Windows | `irm https://raw.githubusercontent.com/KJyang-0114/sift/main/install.ps1 \| iex` |
| Docker（Semgrep 同梱） | `docker run --rm -v "$PWD:/src" ghcr.io/kjyang-0114/sift:latest scan .` |
| ソースから（Go 1.26+） | `go install github.com/KJyang-0114/sift/cmd/sift@latest` |

インストーラーは SHA-256 チェックサムを検証し、`SIFT_VERSION`・`SIFT_INSTALL_DIR` に対応します。`sift init` で任意の LLM プロバイダーを設定できます。

## 既存プロジェクトへの導入

```bash
sift scan . --write-baseline sift-baseline.json   # 現在の問題を受け入れる
git add sift-baseline.json
sift scan . --baseline sift-baseline.json --fail-on high
```

baseline は行番号ではなく、ルール・パス・正規化したコード内容で照合します。各エントリに `reason` を書くことができ、`--baseline X --write-baseline X` で更新しても保持されます。受け入れた問題は JSON と SARIF に suppressed として残るため、判断を後から追跡できます。

## CI で使う

**GitHub Actions**：SARIF を Code Scanning にアップロードしてから、ゲートの結果を返します。

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
      - uses: actions/setup-python@v7
        with:
          python-version: "3.13"
      - run: pip install semgrep
      - run: curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | SIFT_INSTALL_DIR="$HOME/.local/bin" bash
      - name: Run Sift
        id: scan
        run: |
          status=0
          sift scan . --format sarif --output sift.sarif --baseline sift-baseline.json --fail-on high || status=$?
          echo "exit_code=$status" >> "$GITHUB_OUTPUT"
      - uses: github/codeql-action/upload-sarif@v4
        if: ${{ !cancelled() && hashFiles('sift.sarif') != '' }}
        with:
          sarif_file: sift.sarif
      - if: ${{ !cancelled() }}
        run: exit ${{ steps.scan.outputs.exit_code }}
```

**GitLab・Jenkins などその他の CI**：[docs/ci](docs/ci/README.md) を参照してください。

## エージェントに直させる

```bash
sift scan . --format llm | claude -p "Fix these issues"
```

自動ループにするには [Claude Code Stop フック](docs/agents.md) を使います。エージェントが終了しようとするたびにスキャンし、新しい高リスクの問題があれば次の指示として返します。スキャンが不完全なときや連続 2 回目はブロックしません。[pre-commit フック](docs/agents.md#pre-commit) もあります。

## コマンド

| コマンド | 用途 |
|---|---|
| `sift scan [path]` | ディレクトリまたはファイルをスキャン |
| `--diff[=REF]` | コミットに対する追跡済みの変更だけ（既定は `HEAD`） |
| `--format terminal\|json\|sarif\|llm` | レポート形式 |
| `--output FILE` | レポートをファイルに書き出し、ターミナルにも表示 |
| `--fail-on SEVERITY`、`--min-confidence LEVEL` | 抑制されていない問題がしきい値に達したら exit `1` |
| `--baseline FILE`、`--write-baseline FILE` | 既存の問題を受け入れる |
| `sift fix FILE --dry-run \| --interactive \| --rollback` | LLM によるパッチ提案（バックアップとロールバック付き） |
| `sift init`、`sift config` | 設定と確認 |

### 終了コード

| コード | 意味 |
|---|---|
| `0` | 解析完了。`--fail-on` に違反する問題なし |
| `1` | 抑制されていない問題が `--fail-on` に達した |
| `2` | オプション・設定・対象・diff ref が無効 |
| `3` | 解析が一部失敗。完了した結果と診断は出力される |
| `4` | 内部エラー、またはレポートを書き込めなかった |

終了コードを返す前に必ずレポートを書き出すので、CI は先にレポートをアップロードできます。

## 設定

`~/.sift/config.toml`（`sift init` で作成）、または `--config FILE`：

```toml
[llm]
provider = "anthropic"   # anthropic | openai | openrouter | ollama | siliconflow | gemini | deepseek | offline
model = "claude-sonnet-4-6"

[scan]
timeout = 120
concurrency = 4

[vulnerabilities]
enabled = true           # パッケージ名とバージョンを OSV.dev に送信する
```

環境変数：`SIFT_LLM_PROVIDER`、`SIFT_LLM_API_KEY`、`SIFT_LLM_MODEL`。`SIFT_VULNERABILITIES=false` で OSV への照会を無効化できます。パッケージ存在確認は引き続き npm・PyPI・Go proxy・crates.io に接続し、接続できない場合はスキャンが partial（exit 3）になります。

## 制限事項

- ルールやモデルの判断には誤検知があり得ます。対応する前に実際のデータフローを確認してください。
- 依存関係チェックは、正確なバージョンに一致する公開済みアドバイザリだけを照合します。未公開の 0-day や、脆弱なコードが実際に呼ばれるかどうかは判定しません。
- `--diff` は未追跡ファイルを含みません。生成されたテストはレビュー用に出力されるだけで、ホスト上では実行されません。

## コントリビュートとセキュリティ

[CHANGELOG](CHANGELOG.md) · [移行ガイド](MIGRATION.md) · [レビューの流れ](docs/REVIEW-WORKFLOW.zh-Hant.md) · Sift 自体の脆弱性は [SECURITY.md](SECURITY.md) に従って非公開で報告してください。

メンテナーは `v*` タグ（と対応する `CHANGELOG.md` の項目）を push するだけでリリースできます。ワークフローがバイナリ、チェックサム、SBOM、provenance、Docker イメージを公開します。

## ライセンス

[MIT](LICENSE)

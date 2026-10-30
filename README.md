<h1 align="center">Sift</h1>

<p align="center">
  <strong>The security gate for AI-written code.</strong><br>
  Scan code and dependencies, block only <em>new</em> high-risk issues in CI,<br>
  and hand findings back to your coding agent to fix.
</p>

<p align="center">
  <a href="https://github.com/KJyang-0114/sift/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/KJyang-0114/sift/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/KJyang-0114/sift/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/KJyang-0114/sift"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center">
  <strong>English</strong> · <a href="README.zh-Hant.md">繁體中文</a> · <a href="README.ja.md">日本語</a>
</p>

<p align="center">
  <img src="assets/terminal-demo.svg" alt="Sift blocks a new command injection and a vulnerable lodash version while hiding 14 accepted findings" width="820">
</p>

## Why Sift

- **Catches what assistants get wrong.** 38 embedded Semgrep rules for injection, XSS, SSRF, unsafe deserialization, hard-coded secrets, JWT and session mistakes.
- **Knows today's CVEs.** Exact lockfile versions are checked against [OSV.dev](https://osv.dev) on every scan. CVEs in the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog become critical; malicious and hallucinated packages are flagged too.
- **Adoptable on day one.** A baseline accepts existing findings, so `--fail-on high` blocks only what a change introduces. Moving code does not resurface accepted findings.
- **Works where you work.** Terminal, GitHub Code Scanning (SARIF), any CI through the Docker image, and Claude Code or pre-commit hooks.
- **Your keys, your choice.** Static and dependency checks need no API key. LLM analysis is optional: Anthropic, OpenAI, Gemini, OpenRouter, DeepSeek, SiliconFlow, or local Ollama.

## How it works

<p align="center">
  <img src="assets/how-it-works.svg" alt="Code flows into rules, dependency and optional semantic analyzers, then a baseline and fail-on policy, then out to the terminal, SARIF, JSON or an agent" width="100%">
</p>

## Quick start

```bash
pip install semgrep
curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | bash
sift scan .
```

| Platform | Install |
|---|---|
| macOS / Linux | `curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh \| bash` |
| Windows | `irm https://raw.githubusercontent.com/KJyang-0114/sift/main/install.ps1 \| iex` |
| Docker (Semgrep included) | `docker run --rm -v "$PWD:/src" ghcr.io/kjyang-0114/sift:latest scan .` |
| From source (Go 1.26+) | `go install github.com/KJyang-0114/sift/cmd/sift@latest` |

The installers verify SHA-256 checksums and accept `SIFT_VERSION` and `SIFT_INSTALL_DIR`. Run `sift init` to configure an optional LLM provider.

## Adopt it in an existing project

```bash
sift scan . --write-baseline sift-baseline.json   # accept what exists today
git add sift-baseline.json
sift scan . --baseline sift-baseline.json --fail-on high
```

Baseline entries match on rule, path and normalized code, not line numbers. Add a `reason` to any entry; refreshing with `--baseline X --write-baseline X` keeps it. Accepted findings stay in JSON and SARIF as suppressed, so the decision remains auditable.

## Use it in CI

**GitHub Actions** — upload SARIF to Code Scanning, then return the gate result:

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

**GitLab, Jenkins and others** — see [docs/ci](docs/ci/README.md).

## Let your agent fix it

```bash
sift scan . --format llm | claude -p "Fix these issues"
```

For a closed loop, the [Claude Code Stop hook](docs/agents.md) runs Sift whenever the agent tries to finish and hands new high-risk findings back as its next instruction. It never blocks on partial scans or twice in a row. A [pre-commit hook](docs/agents.md#pre-commit) is available too.

## Commands

| Command | Purpose |
|---|---|
| `sift scan [path]` | Scan a directory or file |
| `--diff[=REF]` | Only tracked changes against a commit (default `HEAD`) |
| `--format terminal\|json\|sarif\|llm` | Report format |
| `--output FILE` | Write the report to FILE and still show the terminal report |
| `--fail-on SEVERITY`, `--min-confidence LEVEL` | Exit `1` when an unsuppressed finding reaches the threshold |
| `--baseline FILE`, `--write-baseline FILE` | Accept existing findings |
| `sift fix FILE --dry-run \| --interactive \| --rollback` | LLM-proposed patches with a backup and rollback |
| `sift init`, `sift config` | Configure and inspect settings |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Analysis completed; no finding violates `--fail-on` |
| `1` | An unsuppressed finding reached `--fail-on` |
| `2` | Invalid option, configuration, target or diff ref |
| `3` | Partial analysis; completed findings and diagnostics are still reported |
| `4` | Internal error or the report could not be written |

The report is always written before the exit code is returned, so CI can upload it first.

## Configuration

`~/.sift/config.toml` (created by `sift init`), or `--config FILE`:

```toml
[llm]
provider = "anthropic"   # anthropic | openai | openrouter | ollama | siliconflow | gemini | deepseek | offline
model = "claude-sonnet-4-6"

[scan]
timeout = 120
concurrency = 4

[vulnerabilities]
enabled = true           # sends package names and versions to OSV.dev
```

Environment variables: `SIFT_LLM_PROVIDER`, `SIFT_LLM_API_KEY`, `SIFT_LLM_MODEL`, and `SIFT_VULNERABILITIES=false` to skip OSV lookups. Package verification still contacts npm, PyPI, the Go proxy or crates.io; without network access the scan is partial (exit 3).

## Limits

- Rules and model judgments can produce false positives; confirm data flow before acting.
- Dependency checks match published advisories for exact versions. They do not detect undisclosed 0-days or whether vulnerable code is reachable.
- `--diff` excludes untracked files. Generated tests are exported for review, never executed on the host.

## Contributing and security

[CHANGELOG](CHANGELOG.md) · [Migration guide](MIGRATION.md) · [Review workflow](docs/REVIEW-WORKFLOW.zh-Hant.md) · Report vulnerabilities in Sift privately via [SECURITY.md](SECURITY.md).

Maintainers release by pushing a `v*` tag with a matching `CHANGELOG.md` section; the workflow publishes binaries, checksums, SBOMs, provenance and the Docker image.

## License

[MIT](LICENSE)

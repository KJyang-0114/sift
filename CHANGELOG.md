# Changelog

## v1.6.0 — 2026-10-30

Sift can now gate pull requests: it checks dependencies against today's CVEs,
accepts existing findings through a baseline, blocks only new high-risk
issues, and runs as a GitHub Action, a Docker image or a coding-agent hook.

### Upgrading

- Building from source needs Go 1.26 or later.
- Dependency lookups to OSV.dev are on by default; set `SIFT_VULNERABILITIES=false` to skip them.
- Rule severities changed: each rule declares its own level, so `--fail-on` blocks a different set of findings than the old global mapping. Heuristic rules report with low confidence and do not block at the default `--min-confidence medium`.
- `sift.session-cookie-no-httponly` now covers JavaScript and TypeScript only; Python and Go use new rule IDs.
- Semgrep rule IDs no longer include a random temporary directory, so GitHub Code Scanning alerts from v1.5.0 close once and reopen under stable IDs.

See [MIGRATION.md](MIGRATION.md) for details.

### Rules

- Calibrate every built-in rule with an explicit severity and `metadata.confidence`; heuristic rules report with low confidence instead of blocking. `--min-confidence` now defaults to `medium`, and legacy `ERROR`/`WARNING`/`INFO` levels map to high/medium/low.
- Fix rules that reported correct code: `rate-limit-missing` now flags Express apps without a limiter (it flagged apps that had one), `session-cookie-no-httponly` skips cookies with `httpOnly: true`, and `error-unhandled-rejection` flags handlers that discard the error instead of every `process.on`.
- Narrow `config-env-file` to `.env` file names (not `process.env`), `error-stack-trace-leak` to error details sent to clients (it now also catches Go `http.Error(w, err.Error(), …)`), `frontend-localStorage` to credential-like keys or values, and `path-traversal-file-op` to paths not anchored to a literal or the program's own location.
- Add `session-cookie-no-httponly-python` and `session-cookie-no-httponly-go`. Every changed rule has `semgrep --test` cases.
- `sift.ssrf-http-request` no longer reports every `.get()` call (such as Python `dict.get` or JavaScript `Map.get`); the generic pattern now requires an HTTP-client receiver and a non-literal URL. Rule test cases run with `semgrep --test` in CI.

### Known vulnerabilities

- Match exact lockfile versions (npm, PyPI, Go, crates.io) against OSV.dev advisories, including OpenSSF malicious-package records.
- Raise CVEs listed in the CISA Known Exploited Vulnerabilities catalog to critical with `[Known Exploited]` evidence.
- Merge aliased advisories into one finding and recommend the fix for the installed release line.
- Report OSV outages as partial scans; disable lookups with `[vulnerabilities] enabled = false` or `SIFT_VULNERABILITIES=false`.

### Agent integration

- Add a Claude Code Stop hook that hands new high-risk findings back to the agent in LLM format, with loop protection.
- Add pre-commit hook definitions (`sift` builds from source, `sift-system` uses the installed binary).

### Finding gate

- Add `--fail-on` and `--min-confidence`; exit code `1` when unsuppressed findings reach the threshold, after the report is written.
- Add `--baseline` and `--write-baseline` with line-independent matching so existing findings do not block CI and hand-written reasons survive refreshes.
- Add `--output` to write the selected report to a file while showing the terminal report.
- Fix Semgrep rule IDs that embedded the random temporary rules directory, which made every scan look like new rules in Code Scanning.

### Distribution

- Add a GitHub Action (`uses: KJyang-0114/sift@v1`) that installs pinned Semgrep and Sift, scans once, uploads SARIF, writes a job summary and returns the gate result; releases move the `v1` tag.
- Publish a multi-arch Docker image (`ghcr.io/kjyang-0114/sift`) with a pinned Semgrep and git on each release.
- Add `install.ps1` for Windows with checksum verification, `SIFT_VERSION` and `SIFT_INSTALL_DIR`.
- Add GitLab CI and generic CI templates under `docs/ci/`.
- Publish releases from tags with GoReleaser, SBOMs and build provenance; `install.sh` verifies checksums, fails instead of falling back to an old version, and installs without sudo when needed.

### Security and dependencies

- Read dependency manifests only as regular files inside the scan root, like the lockfile scanner.
- Keep `--baseline` and `--write-baseline` files inside the working directory.
- Update `golang.org/x/sys` (CVE-2026-39824) and other Go modules; require Go 1.26.

## v1.5.0 — 2026-09-09

This release advances from v0.1.1 to the requested v1.5.0 release line.

### Scan reliability

- Preserve partial findings and diagnostics in terminal, JSON, SARIF and LLM output.
- Validate explicit configuration, providers, concurrency, timeout and output formats.
- Preserve partial-scan failures through the fix command; generation and apply failures return nonzero.
- Support file targets, tracked Git changes and empty diffs with valid reports.
- Distinguish registry failures from nonexistent packages.
- Use rooted file operations and reject escaping symlinks.
- Narrow shell, LLM-call, environment-file and file-open heuristics to avoid unrelated identifiers and argument-array subprocess calls. These remain heuristics, not dataflow proofs.
- Allow Ollama analysis without an API key.

### Fix and generated-test workflow

- Add `sift fix FILE --rollback`, without model credentials.
- Prevent incompatible fix modes, propagate cancellation to model requests and cap attempts.
- Require a backup before applying a patch and never overwrite existing backups.
- Reject ambiguous or substring-only patch matches.
- Describe patches as applied, not verified fixes.
- Export Python tests with `[execution] generate = true` to `.sift/generated-tests/`.
- Skip default test generation without model calls; never execute generated code on the host.

### Distribution

- Provide Linux, macOS and Windows binaries for amd64 and arm64, plus SHA-256 checksums.
- Embed v1.5.0 version, commit and build timestamp in release binaries.

### Boundaries

Semgrep is installed separately. Static findings remain advisory (exit 0 when analysis
completes); partial analysis returns 3. Registry checks require network even without
an LLM. Generated tests require human review and manual execution. Container execution,
automatic verification of fixes and complete incremental caching are not included.
See MIGRATION.md for details.

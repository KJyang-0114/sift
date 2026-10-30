# Changelog

## Unreleased

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

- Publish a multi-arch Docker image (`ghcr.io/kjyang-0114/sift`) with a pinned Semgrep and git on each release.
- Add `install.ps1` for Windows with checksum verification, `SIFT_VERSION` and `SIFT_INSTALL_DIR`.
- Add GitLab CI and generic CI templates under `docs/ci/`.

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

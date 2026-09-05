# Migration Guide

## Scan reliability follow-up (unreleased)

`sift scan` now preserves partial findings and reports operational failures with
distinct exit codes. Existing automation that assumed every completed process
returned zero must handle the following contract:

| Exit code | Meaning |
| --- | --- |
| `0` | Enabled analysis completed. Findings remain advisory. |
| `1` | Reserved for a future finding policy gate; not emitted by `scan` yet. |
| `2` | Invalid CLI options, configuration, target, or Git diff reference. |
| `3` | Analysis is incomplete, including analyzer errors, registry failures, or cancellation during analysis. Successful findings remain in the report. |
| `4` | Internal failure, including inability to write the report. |

A report write failure takes precedence over partial analysis. Error-severity
diagnostics make a scan partial; informational and warning diagnostics do not.
History/cache persistence warnings do not invalidate completed analysis.

### Reports and CI

- JSON adds `status: "complete" | "partial"`. This is an additive field; the
  Finding schema remains version 2.
- SARIF uses `invocations[].executionSuccessful: false` for partial analysis.
- Terminal and LLM reports include status and diagnostics. Zero findings during
  a partial scan no longer produce a clean-scan claim.
- An empty tracked Git diff produces a complete, empty report in every format.
- Semgrep's structured `errors` are retained even when Semgrep exits zero.
  Warnings inside that array also indicate incomplete analysis. Semgrep exit 1
  is accepted as a findings-only exit only when a valid report contains findings;
  other nonzero exits retain parsed findings and add an execution diagnostic.
- Semgrep stdout is capped at 32 MiB. Failure stderr is capped at 2 KiB and
  included in the diagnostic; exceeding the stdout cap produces a partial scan.
- Configured LLM request/parsing failures and empty generated-test responses
  produce error diagnostics. Analyzer initialization failures return code 2
  rather than silently omitting the configured analyzer.
- Renderers return output errors to callers instead of printing fallback JSON.

Capture status without discarding the report:

```sh
scan_status=0
sift scan . --format sarif > sift-results.sarif || scan_status=$?
# Upload the valid report before returning the captured status.
exit "$scan_status"
```

The repository workflow now scans once, uploads valid SARIF even for partial
analysis, and then returns the scan exit code. It does not yet gate on findings.

Semgrep exit semantics follow its [CLI reference](https://docs.semgrep.dev/cli-reference#exit-codes).

### Configuration, targets, and local state

`--config FILE` now selects a required explicit configuration file for `scan`,
`fix`, and `config`. Missing files fail rather than silently using defaults.
The current precedence is defaults → selected file → environment → scan flags.
Project-level `.sift.toml` discovery and layered policy remain future work.

`scan` validates output format, positive timeout/concurrency, and supported sandbox
before starting. `--quiet` suppresses the terminal report but retains diagnostics;
JSON, SARIF, and LLM reports remain available under `--quiet`. `--verbose` writes
a summary to stderr and cannot be combined with `--quiet`.

Git diff uses NUL-delimited paths and respects the selected file/subdirectory.
It includes tracked staged and unstaged changes against the selected commit,
excludes deleted and untracked files, and no longer falls back to a full scan
when the reference is invalid. Full resolver/symlink policy remains in Stage A3.

State is now written under the scan target root (the containing directory for a
single-file target), rather than the shell's current working directory. Existing
state in another directory is left in place. The cache is still not used to skip
analysis; this change does not claim incremental caching is complete.

### Semgrep installation

Scanning no longer runs pip or Homebrew automatically. Install Semgrep explicitly
before scanning, for example with `pip install semgrep` in an appropriate Python
environment. Missing Semgrep creates an operational diagnostic and exit code 3.

### Package verification

- Public registry results are classified as exists, missing, or unknown.
- HTTP 401/403, rate limiting, 5xx responses, transport errors, and malformed Cargo
  responses are unknown diagnostics, not missing-package findings.
- Transient transport/429/500/502/503/504 failures retry at most twice. Backoff and
  Retry-After waits respect cancellation. Retry-After values above the two-second
  retry budget are returned as unknown without retrying earlier than requested.
- Missing scoped npm packages and unavailable Go modules are unknown because the
  public endpoint cannot establish whether a private dependency exists.
- A confirmed missing public package is a medium-severity advisory. Its message
  does not claim malware or typosquatting. The existing rule ID is retained for
  consumers; confidence describes the public not-found response only.
- Go `require (...)` blocks are now parsed and uppercase module paths use the
  [Go proxy case encoding](https://go.dev/ref/mod#goproxy-protocol). Replacement,
  workspace, and custom/private registry resolution remain future work.

### Rollback of this follow-up

Revert this change's application, workflow, and documentation together. Consumers
may ignore the additive JSON `status` field. No destructive database migration
is introduced. Reverting restores the old operational behavior, including zero
exit codes on analyzer failures; account for that in CI policy. Target-root state
created by this version is not deleted automatically.

## v0.1 to v0.2 Finding and Analyzer Contracts

Sift v0.2 introduces an intentionally breaking Finding v2 contract. The change adds stable identity, analyzer provenance, confidence, evidence, remediation, typed diagnostics, and safe repository-relative locations.

The CLI command names and current scan defaults are unchanged in this pull request. Privacy policy, explicit upload consent, and generated-code execution policy are delivered in later Stage A pull requests.

## JSON report envelope

The report and each finding now carry `schema_version: "2"`. Empty `findings` and `diagnostics` collections serialize as `[]`, never `null`.

The report `target` no longer exposes an absolute host path. An absolute scan root such as `/home/alice/work/service` is represented as `service`.

Old envelope:

```json
{
  "tool": "sift",
  "target": "/home/alice/work/service",
  "findings": []
}
```

New envelope:

```json
{
  "schema_version": "2",
  "tool": "sift",
  "version": "0.2",
  "target": "service",
  "findings": [],
  "diagnostics": []
}
```

## Finding field mapping

| Finding v1 | Finding v2 | Notes |
| --- | --- | --- |
| `id` | `id` | Now deterministic and includes analyzer/rule identity plus a digest prefix. Do not parse its internal format. |
| none | `fingerprint` | Stable `sha256:<hex>` value for comparison and future deduplication. |
| none | `source` | Analyzer namespace such as `semgrep`, `package-verifier`, or `llm-semantic`. |
| `rule` | `rule` | Stable analyzer rule identifier. |
| `severity` | `severity` | Still `critical`, `high`, `medium`, `low`, or `info`. |
| `category` | `category` | Normalized category. |
| none | `confidence` | `high`, `medium`, or `low`; LLM-only findings default to `low`. |
| `file` | `location.path` | Repository-relative, slash-separated, and never an absolute host path. |
| `line` | `location.line` | Primary start line. |
| `column` | `location.column` | Primary start column. |
| none | `location.end_line`, `location.end_column` | Optional end range. |
| none | `related_locations` | Optional related source ranges; always an array. |
| `code` | `evidence[].snippet` | Evidence is typed and bounded. |
| none | `evidence[].kind` | `code`, `dependency`, `execution`, `model`, or `other`. |
| `message` | `message` | Human-readable finding description. |
| none | `remediation` | Required remediation guidance. |
| none | `help_uri` | Optional rule documentation URL. |
| `cwe` | `cwe` | Preserved. |
| `owasp` | `owasp` | Preserved. |
| none | `suppression` | Audit-visible `{suppressed, reason}` state. Policy evaluation arrives later. |

Consumers should key long-lived records by `fingerprint`, not array order, message text, or the display-oriented `id`.

The authoritative machine-readable schema is [`docs/schemas/finding-v2.schema.json`](docs/schemas/finding-v2.schema.json).

## Analyzer API

Finding v1 analyzers accepted one string, which also encoded comma-separated paths in diff mode:

```go
type Analyzer interface {
    Name() string
    Analyze(target string) ([]Finding, error)
}
```

Finding v2 analyzers accept cancellation and an immutable request with a root and target slice:

```go
type Analyzer interface {
    Name() string
    Analyze(context.Context, core.ScanRequest) core.AnalysisResult
}
```

Use `core.NewScanRequest` to construct requests. `Targets()` and `AbsoluteTargets()` return defensive copies. A filename containing a comma is now one target rather than an accidental list.

`AnalysisResult` preserves successful findings and typed diagnostics together. Expected analyzer, integration, timeout, cancellation, and target conditions are diagnostics and are not converted into security findings.

## Diagnostics

JSON reports expose a top-level `diagnostics` array. SARIF reports expose the same conditions as `toolExecutionNotifications`.

Diagnostic kinds are:

- `configuration`
- `policy`
- `target`
- `analyzer`
- `integration`
- `internal`

Diagnostic severities are `info`, `warning`, and `error`. Registry transport failures now produce `registry.unavailable` diagnostics instead of silently disappearing or creating a missing-package finding.

## SARIF

SARIF remains version 2.1.0. Results now include:

- `partialFingerprints["sift/v2"]`;
- source, category, confidence, remediation, and suppression properties;
- start/end ranges and related locations;
- rule `helpUri` when available;
- audit-visible suppressions;
- analyzer diagnostics as invocation notifications.

## SQLite history

The `.sift/findings.db` migration is additive. Sift adds v2 columns to an existing `findings` table and does not delete scans or findings.

When a v1 row is read, Sift synthesizes a v2 finding with:

- `source: "legacy"`;
- `confidence: "low"`;
- a stable generated ID and fingerprint;
- legacy code stored as typed evidence;
- repository-safe fallback paths.

New rows retain complete Finding v2 fields, including evidence and suppression state.

## Go package changes

The v1 model in `internal/static` was removed. Internal consumers now import `internal/core` for:

- `Finding` and `FindingInput`;
- `Severity` and `Confidence`;
- `ScanRequest` and `Analyzer`;
- `AnalysisResult` and `Diagnostic`.

`scan.Orchestrator.LastFindings()` now returns `[]core.Finding`. `LastDiagnostics()` returns `[]core.Diagnostic`.

## Rollback

Reverting the application code does not remove or rewrite old SQLite rows. Added columns remain unused by v0.1 code. Before rolling back an automation that consumes JSON or SARIF, restore its v1 field mapping because v2 nested locations and evidence are not backward compatible.

To keep a v2 report before rollback:

```sh
sift scan . --format json > sift-v2-report.json
```

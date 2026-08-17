# Migration Guide

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

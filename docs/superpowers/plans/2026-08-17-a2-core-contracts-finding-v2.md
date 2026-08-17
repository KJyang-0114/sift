# A2 Core Contracts and Finding v2 Implementation Plan

Date: 2026-08-17
Status: In progress
Branch: `codex/a2-core-contracts-finding-v2`
Target PR: Stage A #2

## Goal

Replace the implicit v1 analyzer and finding contracts with typed, testable v2 contracts that every later hardening stage can depend on. The final branch must compile and test on Linux, macOS, and Windows, publish no absolute host paths or secrets, and document every breaking output/API change.

## Scope

- Add a dedicated `internal/core` package for Finding v2, immutable scan requests, analyzer outcomes, and typed diagnostics.
- Generate deterministic finding IDs and SHA-256 fingerprints from analyzer namespace, rule, repository-relative path, and a stable location/message key.
- Migrate Semgrep, dependency verification, LLM semantic analysis, generated-test analysis, batch analysis, scan orchestration, cache/store consumers, and all reporters.
- Upgrade JSON and SARIF contracts and add deterministic contract tests.
- Upgrade SQLite persistence without destroying existing scan history.
- Add `MIGRATION.md` describing v1-to-v2 changes.

## Out of scope

- Symlink-aware target containment and NUL-delimited Git target discovery (A3).
- Upload consent and provider key policy (A4).
- Command runner and container-only generated-code execution (A5).
- Finding deduplication, baselines, and suppressions policy evaluation (B1). This PR carries suppression state in the schema only.
- Dependency registry accuracy redesign (B2).

## Contract decisions

### Finding v2

Serialized findings use `schema_version: "2"` and contain:

- stable `id` and `fingerprint`;
- `source`, `rule`, normalized `severity`, `category`, and `confidence`;
- `location` plus optional `related_locations`;
- bounded typed `evidence`;
- `message`, `remediation`, optional `help_uri`, `cwe`, and `owasp`;
- explicit `suppression` state.

Locations serialize repository-relative slash-separated paths. Constructors reject absolute paths, traversal, missing source/rule/message/location, invalid enum values, and oversized evidence. Fingerprints serialize as `sha256:<hex>` and never include evidence snippets, secrets, or an absolute root.

### Analyzer v2

`Analyzer.Analyze` accepts `context.Context` and an immutable `ScanRequest`. It returns an `AnalysisResult` containing findings and typed diagnostics. Expected analyzer, integration, timeout, and cancellation conditions are diagnostics instead of fabricated findings or untyped errors.

Dependencies remain constructor-injected. The narrower external integration interfaces themselves arrive in A5.

### Compatibility

This is an intentionally breaking internal and JSON schema change. The CLI commands and current default behavior remain unchanged. `MIGRATION.md` is required in the same PR.

## Task 1: Core enums, Finding v2, and stable identity

**Files:**

- Add `internal/core/finding.go`
- Add `internal/core/finding_test.go`
- Add `internal/core/severity.go`
- Add `internal/core/severity_test.go`

- [x] Write failing table tests for enum validation and severity filtering/grouping.
- [x] Write failing tests for required fields, safe relative paths, bounded evidence, deterministic IDs/fingerprints, stable slash normalization, and secret/absolute-root exclusion.
- [x] Implement the smallest typed model and constructor that passes the tests.
- [x] Run `go test ./internal/core -count=1`.
- [x] Commit as `feat: add Finding v2 core model`.

## Task 2: Immutable requests and typed analyzer outcomes

**Files:**

- Add `internal/core/analyzer.go`
- Add `internal/core/analyzer_test.go`
- Modify `internal/static/analyzer.go`

- [x] Write failing tests proving constructor validation and defensive copies for target slices.
- [x] Add typed diagnostic kinds/severities, `AnalysisResult`, and the context-aware `Analyzer` interface.
- [ ] Preserve severity helper behavior in `internal/core`; remove the v1 model from `internal/static`.
- [ ] Add compile-time interface assertions to analyzer implementations as they migrate.
- [x] Run focused tests and commit as `feat: add analyzer v2 contracts`.

## Task 3: Migrate deterministic and network analyzers

**Files:**

- Modify `internal/static/semgrep.go`
- Add/modify Semgrep parser tests
- Modify `internal/agent/package_verify.go`
- Add dependency verifier contract tests

- [ ] Add failing parser tests for v2 identity, repository-relative locations, code evidence, confidence, remediation, and safe path rejection.
- [ ] Migrate Semgrep to `Analyze(context.Context, core.ScanRequest)` and use request cancellation.
- [ ] Add failing dependency tests proving unavailable registries create diagnostics, never malicious-package findings.
- [ ] Migrate package verification and emit dependency evidence with typed diagnostics.
- [ ] Run focused tests and commit as `refactor: migrate deterministic analyzers to v2`.

## Task 4: Migrate optional LLM and generated-test analyzers

**Files:**

- Modify `internal/agent/semantic.go`
- Modify `internal/agent/tester.go`
- Modify `internal/scan/batch.go`
- Add focused parser/contract tests

- [ ] Add failing tests that LLM-only findings default to low confidence and carry explicit provenance/evidence.
- [ ] Pass caller context through LLM calls instead of creating background contexts.
- [ ] Convert per-file failures and execution failures to typed diagnostics where they are environmental rather than security findings.
- [ ] Migrate batch parsing to the v2 model and standard JSON decoding where practical.
- [ ] Run focused tests and commit as `refactor: migrate optional analyzers to v2`.

## Task 5: Migrate orchestration and worker contracts

**Files:**

- Modify `internal/scan/orchestrator.go`
- Modify `internal/scan/pool.go`
- Modify `internal/scan/pool_test.go`
- Add orchestrator contract tests

- [ ] Add failing tests for context cancellation, diagnostic preservation, result ordering, and immutable request propagation.
- [ ] Make analyzer scheduling context-aware and return findings plus diagnostics without discarding successful partial results.
- [ ] Stop transporting multiple targets as comma-separated strings; use request target slices.
- [ ] Keep exit-code policy changes out of this PR while preserving non-zero fatal errors.
- [ ] Run `go test ./internal/scan -count=1` and commit as `refactor: run analyzers through v2 contracts`.

## Task 6: Upgrade reports and persistence

**Files:**

- Modify `internal/report/*.go`
- Modify `internal/report/*_test.go`
- Modify `internal/store/sqlite.go`
- Add `internal/store/sqlite_test.go`

- [ ] Add failing JSON contract tests for schema version, empty arrays, safe paths, evidence, confidence, and suppression state.
- [ ] Add failing SARIF tests for fingerprints, locations, help/remediation, confidence properties, and empty arrays.
- [ ] Migrate terminal and LLM renderers without panics on empty IDs or locations.
- [ ] Add additive SQLite migration tests using a v1 fixture schema; preserve old rows and round-trip v2 rows.
- [ ] Run report/store tests and commit as `feat: publish Finding v2 reports and history`.

## Task 7: Migrate remaining consumers and document breaking changes

**Files:**

- Modify `internal/agent/fixer.go`
- Modify `internal/cache/filecache.go` if required
- Modify command/report consumers found by compiler/search
- Add `MIGRATION.md`

- [ ] Use compiler failures and `rg 'static\.Finding|\.File|\.Line|\.Code'` to migrate every remaining v1 consumer.
- [ ] Document JSON field mappings, analyzer interface changes, fingerprint behavior, persistence migration, and rollback.
- [ ] Run formatting, vet, all tests, race tests where supported, and three-platform builds.
- [ ] Commit as `docs: document Finding v2 migration`.

## Task 8: PR verification and handoff

- [ ] Verify a clean tree and run `gofmt -l .`, `go mod verify`, `go vet ./...`, `go test ./... -count=1`, and `git diff --check origin/main...HEAD`.
- [ ] Cross-build `windows/amd64`, `linux/amd64`, and `darwin/amd64` with `CGO_ENABLED=0`.
- [ ] Review that no API key, source-upload, execution opt-in, target resolver, or accuracy-policy work leaked into the branch.
- [ ] Push the branch and open a Draft PR with scope, out-of-scope, tests, security, compatibility, and rollback sections.
- [ ] Wait for CI and the repository security scan; fix failures before marking Ready for review.
- [ ] Do not merge without explicit maintainer authorization.

## Rollback

The PR is isolated on its own branch and can be reverted as a merge unit. SQLite changes must be additive so reverting application code leaves existing databases readable; newly added columns may remain unused. JSON/SARIF consumers must follow `MIGRATION.md` when adopting v2.

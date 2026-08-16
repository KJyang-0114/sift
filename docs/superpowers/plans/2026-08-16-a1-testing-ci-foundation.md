# A1 Testing and CI Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Sift a deterministic automated test suite and required GitHub CI checks without introducing the v0.2 core-interface changes planned for later pull requests.

**Architecture:** Tests stay beside the Go packages they exercise and use only the standard library. Report rendering gains pure encoding helpers so JSON and SARIF can be tested without redirecting process stdout or depending on wall-clock time; public render functions preserve current CLI behavior.

**Tech Stack:** Go 1.25.5, standard `testing` package, GitHub Actions, `actions/setup-go`, `gofmt`, `go vet`, Go race detector.

**Spec:** `docs/superpowers/specs/2026-08-16-sift-v0.2-hardening-design.md`

## Global Constraints

- Linux and macOS receive the complete feature set; Windows remains analysis-only.
- This pull request changes no CLI flags, configuration schema, analyzer interface, or finding schema.
- Tests must not require Semgrep, Docker, a registry, an LLM provider, or an API key.
- All temporary files use `t.TempDir()` and all environment changes use `t.Setenv()`.
- Every production-code change is preceded by a failing test and is limited to testability or a defect exposed by that test.
- CI uses least-privilege `contents: read` permissions.

---

## File map

- `internal/sandbox/process_unix.go`: Linux/macOS process-group setup and cleanup.
- `internal/sandbox/process_windows.go`: Windows-safe process cleanup without Unix syscalls.
- `internal/static/analyzer_test.go`: severity filtering and grouping invariants.
- `internal/securepath/securepath_test.go`: existing absolute-path containment, read, and write contracts.
- `internal/config/config_test.go`: default values, provider model selection, and environment overrides.
- `internal/config/store_test.go`: save/load round trip and restricted file permissions.
- `internal/report/json.go`: pure JSON encoder plus existing stdout wrapper.
- `internal/report/json_test.go`: JSON schema and summary contract.
- `internal/report/sarif.go`: pure SARIF encoder plus existing stdout wrapper.
- `internal/report/sarif_test.go`: SARIF 2.1.0 structure and severity mapping.
- `internal/agent/fixer_test.go`: unified-diff parser and atomic patch behavior.
- `internal/cache/filecache_test.go`: hash-based change detection, persistence, filtering, and purge.
- `internal/scan/pool_test.go`: ordering, concurrency limit, failure statistics, and cache callbacks.
- `.github/workflows/ci.yml`: formatting, vet, test, race, and cross-platform build gates.
- `Makefile`: deterministic `fmt-check`, `test`, `test-race`, and `ci` targets.

### Task 0: Restore the Windows build baseline

**Files:**
- Modify: `internal/sandbox/orbital.go`
- Create: `internal/sandbox/process_unix.go`
- Create: `internal/sandbox/process_windows.go`

**Interfaces:**
- Produces package-private `configureProcessGroup(*exec.Cmd)` and `killProcess(*exec.Cmd)` implementations for supported platforms.
- Preserves Linux/macOS process-group behavior and uses direct process termination on Windows.

- [x] **Step 1: Reproduce the baseline failure**

Run: `go test ./...`
Observed: Windows compilation fails because `syscall.SysProcAttr.Setpgid`, `syscall.Getpgid`, and `syscall.Kill` do not exist on Windows.

- [x] **Step 2: Confirm the root cause in the Go standard library**

Go 1.25.5 defines `Setpgid` and process-group syscalls only for Unix targets, while `orbital.go` had no platform build constraint.

- [x] **Step 3: Split platform-specific process control**

Keep orchestration in `orbital.go`. Implement Unix process-group control in a Linux/macOS build-tagged file and a Windows direct-process fallback in a Windows build-tagged file.

- [x] **Step 4: Re-run the Windows suite**

Run: `go test ./...`
Expected: all packages compile on Windows and the baseline suite passes.

- [x] **Step 5: Cross-compile supported targets**

Run `go build ./cmd/sift/` with `GOOS=windows`, `GOOS=linux`, and `GOOS=darwin` using `CGO_ENABLED=0`.
Expected: all three builds pass.

- [x] **Step 6: Commit**

```bash
git add internal/sandbox/orbital.go internal/sandbox/process_unix.go internal/sandbox/process_windows.go docs/superpowers/plans/2026-08-16-a1-testing-ci-foundation.md
git commit -m "fix: make sandbox process control portable"
```

### Task 1: Static finding helpers

**Files:**
- Create: `internal/static/analyzer_test.go`

**Interfaces:**
- Consumes: `FilterBySeverity([]Finding, Severity) []Finding`, `GroupBySeverity([]Finding) map[Severity][]Finding`.
- Produces: regression coverage for severity ordering and unknown thresholds.

- [x] **Step 1: Write table-driven tests**

```go
func TestFilterBySeverity(t *testing.T) {
	findings := []Finding{
		{ID: "critical", Severity: SeverityCritical},
		{ID: "high", Severity: SeverityHigh},
		{ID: "medium", Severity: SeverityMedium},
		{ID: "low", Severity: SeverityLow},
		{ID: "info", Severity: SeverityInfo},
	}

	got := FilterBySeverity(findings, SeverityMedium)
	want := []string{"critical", "high", "medium"}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("finding %d = %q, want %q", i, got[i].ID, want[i])
		}
	}
}
```

Add `TestGroupBySeverity` to assert empty input and exact grouping for all five severities.

- [x] **Step 2: Run the package test**

Run: `go test ./internal/static -run 'Test(Filter|Group)' -count=1`
Expected: PASS. These tests characterize current behavior and require no production edit.

- [x] **Step 3: Commit**

```bash
git add internal/static/analyzer_test.go
git commit -m "test: cover finding severity helpers"
```

### Task 2: Secure path and configuration contracts

**Files:**
- Create: `internal/securepath/securepath_test.go`
- Create: `internal/config/config_test.go`
- Create: `internal/config/store_test.go`

**Interfaces:**
- Consumes: `ValidatePath`, `ReadFile`, `WriteFile`, `Default`, `LLMConfig.DefaultModel`, `Save`, and `Load`.
- Produces: cross-platform tests for current containment and config persistence behavior.

- [x] **Step 1: Write secure-path tests**

```go
func TestValidatePathRejectsOutsideAbsolutePath(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if _, err := ValidatePath(base, outside); err == nil {
		t.Fatal("ValidatePath accepted a path outside the base directory")
	}
}

func TestReadWriteFileInsideBase(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nested.txt")
	if err := WriteFile(base, path, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(base, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "safe" {
		t.Fatalf("content = %q, want safe", got)
	}
}
```

Do not add relative-path or symlink expectations in A1; those contracts belong to A3's resolver redesign.

- [x] **Step 2: Write configuration tests**

```go
func TestLoadAppliesEnvironmentOverrides(t *testing.T) {
	setTestHome(t)
	t.Setenv("SIFT_LLM_PROVIDER", "openai")
	t.Setenv("SIFT_LLM_API_KEY", "test-key")
	t.Setenv("SIFT_LLM_MODEL", "test-model")

	cfg, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.Provider != ProviderOpenAI || cfg.LLM.APIKey != "test-key" || cfg.LLM.Model != "test-model" {
		t.Fatalf("environment overrides not applied: %#v", cfg.LLM)
	}
}
```

`setTestHome` sets both `HOME` and `USERPROFILE` to one temporary directory. Add tests for `Default`, every provider's `DefaultModel`, save/load round trip, directory permission `0700`, and non-Windows file permission no broader than `0600`.

- [x] **Step 3: Run tests and observe the permission failure**

Run: `go test ./internal/securepath ./internal/config -count=1`
Observed on Windows: `securepath` passed and the environment-override test failed because `Load` returned before applying overrides when no config file existed. The Unix permission assertion is platform-gated and will run in CI; code inspection confirmed `os.Create` did not force `0600`.

- [x] **Step 4: Make config save permissions deterministic**

Replace `os.Create(path)` with:

```go
f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
```

After encoding and closing, call `os.Chmod(path, 0o600)` on non-Windows systems so an existing broader file is tightened.

- [x] **Step 5: Re-run tests**

Run: `go test ./internal/securepath ./internal/config -count=1`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add internal/securepath/securepath_test.go internal/config/config_test.go internal/config/store_test.go internal/config/store.go
git commit -m "test: lock down path and config contracts"
```

### Task 3: Pure JSON and SARIF encoders

**Files:**
- Modify: `internal/report/json.go`
- Create: `internal/report/json_test.go`
- Modify: `internal/report/sarif.go`
- Create: `internal/report/sarif_test.go`

**Interfaces:**
- Produces: `encodeJSON(findings []static.Finding, target string, duration time.Duration, now time.Time) ([]byte, error)`.
- Produces: `encodeSARIF(findings []static.Finding) ([]byte, error)`.
- Preserves: `RenderJSON` and `RenderSARIF` stdout behavior.

- [x] **Step 1: Write failing JSON encoder tests**

```go
func TestEncodeJSONSummaryAndEmptyFindings(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	data, err := encodeJSON(nil, "repo", 1500*time.Millisecond, now)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Tool string `json:"tool"`
		Timestamp string `json:"timestamp"`
		Duration string `json:"duration"`
		Findings []static.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Tool != "sift" || got.Timestamp != now.Format(time.RFC3339) || got.Duration != "1.50s" || got.Findings == nil {
		t.Fatalf("unexpected report: %#v", got)
	}
}
```

Add a second test with critical/high/medium/low/info findings and assert every summary count.

- [x] **Step 2: Verify JSON tests fail**

Run: `go test ./internal/report -run TestEncodeJSON -count=1`
Expected: FAIL because `encodeJSON` does not exist.

- [x] **Step 3: Extract the JSON encoder**

Move report construction into `encodeJSON`, inject `now`, return marshal errors, and keep:

```go
func RenderJSON(findings []static.Finding, target string, duration time.Duration) {
	out, err := encodeJSON(findings, target, duration, time.Now())
	if err != nil {
		fmt.Printf("{\"error\":%q}\n", err.Error())
		return
	}
	fmt.Println(string(out))
}
```

- [x] **Step 4: Write failing SARIF encoder tests**

Parse the returned document into `map[string]any` and assert schema/version, one unique rule descriptor for duplicate rules, severity mapping, `startColumn` normalization to `1`, and empty `results` encoded as `[]` rather than `null`.

- [x] **Step 5: Verify SARIF tests fail**

Run: `go test ./internal/report -run TestEncodeSARIF -count=1`
Expected: FAIL because `encodeSARIF` does not exist and empty slices currently marshal as `null`.

- [x] **Step 6: Extract the SARIF encoder**

Move SARIF construction into `encodeSARIF`, initialize rule/result slices, return `json.MarshalIndent` errors, and make `RenderSARIF` a stdout wrapper.

- [x] **Step 7: Run all report tests**

Run: `go test ./internal/report -count=1`
Expected: PASS.

- [x] **Step 8: Commit**

```bash
git add internal/report/json.go internal/report/json_test.go internal/report/sarif.go internal/report/sarif_test.go
git commit -m "test: add deterministic report contracts"
```

### Task 4: Unified-diff patch regression suite

**Files:**
- Create: `internal/agent/fixer_test.go`

**Interfaces:**
- Consumes package-private `parseHunks`, `applySingleHunk`, and `applyPatch`.
- Produces regression coverage for exact, multi-hunk, whitespace-tolerant, malformed, and atomic-failure behavior.

- [x] **Step 1: Write table-driven patch tests**

```go
func TestApplyPatch(t *testing.T) {
	tests := []struct {
		name string
		original string
		patch string
		want string
		wantErr bool
	}{
		{"single hunk", "a\nunsafe\nz\n", "@@ -2,1 +2,1 @@\n- unsafe\n+ safe", "a\nsafe\nz\n", false},
		{"multiple hunks", "one\ntwo\nthree\n", "@@ -1,1 +1,1 @@\n- one\n+ ONE\n@@ -3,1 +3,1 @@\n- three\n+ THREE", "ONE\ntwo\nTHREE\n", false},
		{"missing old content is atomic", "original\n", "@@ -1,1 +1,1 @@\n- absent\n+ replacement", "original\n", true},
		{"empty patch", "original\n", "explanation only", "original\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyPatch(tt.original, tt.patch)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("got %q, err %v; want %q, error=%v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}
```

Add cases for file headers, trailing whitespace, no-op replacement, and a second hunk failing after the first to prove the original is returned.

- [x] **Step 2: Run the tests**

Run: `go test ./internal/agent -run 'Test(Parse|Apply)' -count=1`
Expected: PASS unless a regression is exposed. If one fails, add the smallest production fix and retain the failing case.

- [x] **Step 3: Commit**

```bash
git add internal/agent/fixer_test.go internal/agent/fixer.go
git commit -m "test: cover unified diff application"
```

### Task 5: Cache and worker-pool concurrency tests

**Files:**
- Create: `internal/cache/filecache_test.go`
- Create: `internal/scan/pool_test.go`

**Interfaces:**
- Consumes: `NewFileCache`, `IsChanged`, `MarkScanned`, `FilterChanged`, `Save`, `Stats`, `Purge`, `NewWorkerPool`, `Run`, and `ScanWithCache`.
- Produces race-detector coverage for shared cache/pool state.

- [x] **Step 1: Write cache lifecycle tests**

Create a file under `t.TempDir()`, assert it starts changed, mark and save it, reload the cache, assert unchanged, modify equal-length content, assert changed, then purge and assert zero cached files. Add a `FilterChanged` case containing one missing file and assert conservative inclusion.

- [x] **Step 2: Write worker-pool tests**

Use atomics to track active jobs and assert the observed maximum never exceeds `maxWorkers`. Assert results retain input order, one failing job increments `failed`, and `ScanWithCache` invokes `markScanned` only for successful changed files.

```go
pool := NewWorkerPool(2, time.Second)
var active atomic.Int32
var maximum atomic.Int32
jobs := make([]Job, 8)
for i := range jobs {
	jobs[i] = Job{Name: strconv.Itoa(i), Analyze: func() ([]static.Finding, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for current > maximum.Load() && !maximum.CompareAndSwap(maximum.Load(), current) {}
		time.Sleep(10 * time.Millisecond)
		return nil, nil
	}}
}
pool.Run(jobs)
if maximum.Load() > 2 {
	t.Fatalf("observed %d concurrent jobs, want at most 2", maximum.Load())
}
```

- [x] **Step 3: Run normal and race tests**

Run: `go test ./internal/cache ./internal/scan -count=1`
Expected: PASS.

Run: `go test -race ./internal/cache ./internal/scan -count=1`
Expected: PASS on Linux/macOS.

Observed locally: normal Windows tests exposed and verified the `Save`/`Stats` concurrent map bug. The portable Go toolchain could not run `-race` because no C compiler is installed; the Ubuntu required check runs the race detector.

- [x] **Step 4: Commit**

```bash
git add internal/cache/filecache_test.go internal/scan/pool_test.go
git commit -m "test: cover cache and worker pool concurrency"
```

### Task 6: Required CI checks and developer targets

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `Makefile`

**Interfaces:**
- Produces: `fmt-check`, `test`, `test-race`, and `ci` Make targets.
- Produces GitHub checks: `quality` and `build (<os>)`.

- [x] **Step 1: Add deterministic Make targets**

```make
.PHONY: fmt-check test test-race ci

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))"

test:
	go test ./... -count=1

test-race:
	go test -race ./... -count=1

ci: fmt-check
	go vet ./...
	go test ./... -count=1
	go build ./cmd/sift/
```

- [x] **Step 2: Add the GitHub Actions workflow**

Create a least-privilege workflow triggered for pull requests and pushes to `main`. The Ubuntu `quality` job runs format check, vet, all tests, race tests, and build. A matrix job cross-builds natively on `ubuntu-latest`, `macos-latest`, and `windows-latest` using Go `1.25.5`.

```yaml
permissions:
  contents: read

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v7
        with:
          go-version: '1.25.5'
          cache: true
      - run: test -z "$(gofmt -l $(find . -name '*.go' -not -path './vendor/*'))"
      - run: go vet ./...
      - run: go test ./... -count=1
      - run: go test -race ./... -count=1
      - run: go build ./cmd/sift/
```

- [x] **Step 3: Run local equivalents**

Run: `gofmt -w internal/**/*_test.go`

Run: `go vet ./...`

Run: `go test ./... -count=1`

Run: `go test -race ./... -count=1` on a supported local environment; otherwise rely on the Ubuntu required check and state the local limitation in the PR.

Run: `go build ./cmd/sift/`

Expected: all commands PASS.

Observed: formatting, dependency verification, vet, all tests, and the Windows build pass locally. The race test requires GCC and runs in the Ubuntu job. Enabling the formatting gate required a separate mechanical gofmt baseline commit. Vet also exposed an ineffective JSON tag on an unexported cache field; the tag was removed without changing serialization behavior.

- [x] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml Makefile
git commit -m "ci: enforce Go quality and build checks"
```

### Task 7: Pull-request verification and handoff

**Files:**
- Modify: `docs/superpowers/plans/2026-08-16-a1-testing-ci-foundation.md` (check completed steps only).

**Interfaces:**
- Produces a reviewable GitHub pull request targeting `main`.

- [x] **Step 1: Run the full verification suite from a clean status**

Run: `git diff --check`

Run: `go vet ./...`

Run: `go test ./... -count=1`

Run: `go build ./cmd/sift/`

Expected: PASS with no untracked build output.

Observed: the working tree was clean; `gofmt -l .`, `go mod verify`, `go vet ./...`, `go test ./... -count=1`, `git diff --check origin/main...HEAD`, and CGO-disabled builds for Windows, Linux, and macOS amd64 all passed. Local Windows race testing remains unavailable because no GCC toolchain is installed; the Ubuntu quality job runs it.

- [x] **Step 2: Review scope**

Run: `git diff origin/main...HEAD --stat`

Run: `git diff origin/main...HEAD -- . ':(exclude)docs/superpowers/**'`

Confirm there are no CLI, config-schema, analyzer-interface, or Finding-schema changes.

Observed: the non-documentation diff is limited to tests, CI/build tooling, platform-specific sandbox process control, configuration permission/override fixes, deterministic report encoding seams, a cache locking fix, and the repository gofmt baseline. No CLI flags, configuration schema, analyzer interface, or Finding schema changed.

- [ ] **Step 3: Push and open the pull request**

Push `codex/a1-testing-ci-foundation`, open a draft PR against `main`, include tests/security/rollback sections, wait for GitHub checks, then mark ready for maintainer review. Do not merge.

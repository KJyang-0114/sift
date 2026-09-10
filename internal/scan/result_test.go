package scan

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
)

func gitFixture(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root, "-c", "user.name=Sift Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath="}, args...)...)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestAnalyzerInitializationFailureIsConfigurationError(t *testing.T) {
	cfg := config.Default()
	cfg.LLM.Provider = "unsupported"
	cfg.LLM.APIKey = "fixture"
	_, err := NewOrchestrator(cfg).Scan(context.Background(), t.TempDir())
	var operation *core.OperationError
	if !errors.As(err, &operation) || operation.Kind != core.DiagnosticConfiguration {
		t.Fatalf("initialization failure = %v", err)
	}
}

func writeFixture(t *testing.T, root, name, text string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanResetsResultsAndSkipsAnalyzersForEmptyDiff(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "app.py", "print(1)\n")
	gitFixture(t, root, "init", "-q")
	gitFixture(t, root, "add", "app.py")
	gitFixture(t, root, "commit", "-qm", "fixture")
	calls := 0
	orch := &Orchestrator{staticAnalyzers: []core.Analyzer{analyzerStub{name: "fixture", analyze: func(context.Context, core.ScanRequest) core.AnalysisResult {
		calls++
		return core.AnalysisResult{Findings: []core.Finding{{ID: "kept", Severity: core.SeverityHigh}}, Diagnostics: []core.Diagnostic{{Severity: core.DiagnosticError, Code: "fixture.failure"}}}
	}}}}
	result, err := orch.Scan(context.Background(), root)
	if err != nil || result.Err() == nil || len(orch.LastFindings()) != 1 {
		t.Fatalf("first scan: %#v %v", result, err)
	}
	orch.SetDiffMode("HEAD")
	result, err = orch.Scan(context.Background(), root)
	if err != nil || result.Err() != nil || len(result.Findings) != 0 || len(result.Diagnostics) != 0 || calls != 1 {
		t.Fatalf("empty diff: %#v %v calls=%d", result, err, calls)
	}
	if len(orch.LastFindings()) != 0 || len(orch.LastDiagnostics()) != 0 {
		t.Fatal("empty diff retained previous results")
	}
}

func TestInvalidDiffNeverFallsBackToFullScan(t *testing.T) {
	root := t.TempDir()
	gitFixture(t, root, "init", "-q")
	orch := &Orchestrator{diffRef: "missing", staticAnalyzers: []core.Analyzer{analyzerStub{name: "fixture", analyze: func(context.Context, core.ScanRequest) core.AnalysisResult {
		t.Error("unexpected full scan")
		return core.AnalysisResult{}
	}}}}
	_, err := orch.Scan(context.Background(), root)
	var operation *core.OperationError
	if !errors.As(err, &operation) || operation.Kind != core.DiagnosticTarget {
		t.Fatalf("error = %v", err)
	}
}

func TestGitDiffKeepsTargetScopeAndExcludesDeletedFiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"sub/a.go", "sub/b.go", "sub/deleted.go", "outside.go"} {
		writeFixture(t, root, name, "old\n")
	}
	gitFixture(t, root, "init", "-q")
	gitFixture(t, root, "add", ".")
	gitFixture(t, root, "commit", "-qm", "fixture")
	for _, name := range []string{"sub/a.go", "sub/b.go", "outside.go", "untracked.go"} {
		writeFixture(t, root, name, "new\n")
	}
	if err := os.Remove(filepath.Join(root, "sub/deleted.go")); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, root, "add", "sub/a.go")
	for _, test := range []struct {
		target      string
		paths, want []string
	}{
		{filepath.Join(root, "sub"), []string{"."}, []string{"a.go", "b.go"}},
		{filepath.Join(root, "sub"), []string{"b.go"}, []string{"b.go"}},
	} {
		got, err := gitChangedFiles(context.Background(), test.target, "HEAD", test.paths)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Fatalf("diff = %#v, want %#v, err=%v", got, test.want, err)
		}
	}
}

func TestGitDiffPreservesUnusualFilenames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filenames cannot contain newline")
	}
	root := t.TempDir()
	name := "space,中文\nfile.go"
	writeFixture(t, root, name, "old\n")
	gitFixture(t, root, "init", "-q")
	gitFixture(t, root, "add", ".")
	gitFixture(t, root, "commit", "-qm", "fixture")
	writeFixture(t, root, name, "new\n")
	got, err := gitChangedFiles(context.Background(), root, "HEAD", []string{"."})
	if err != nil || !reflect.DeepEqual(got, []string{name}) {
		t.Fatalf("diff = %#v, err=%v", got, err)
	}
}

func TestScanCancellationCannotReportSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := (&Orchestrator{}).Scan(ctx, t.TempDir())
	if err != nil || result.Err() == nil || result.Status() != "partial" {
		t.Fatalf("cancelled scan = %#v, err=%v", result, err)
	}
}

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
	"github.com/spf13/cobra"
)

type scannerStub struct {
	result core.ScanResult
	err    error
	ref    string
	ctx    context.Context
}

func (s *scannerStub) SetDiffMode(ref string) { s.ref = ref }
func (s *scannerStub) Scan(ctx context.Context, _ string) (core.ScanResult, error) {
	s.ctx = ctx
	return s.result, s.err
}

func scanRootForTest(t *testing.T, factory func(*config.Config) scanService) (*cobra.Command, string) {
	t.Helper()
	t.Setenv("SIFT_LLM_PROVIDER", "offline")
	t.Setenv("SIFT_LLM_API_KEY", "")
	t.Setenv("SIFT_LLM_MODEL", "")
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[llm]\nprovider = 'offline'\n[output]\nformat = 'json'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := NewRootCmd("test", "test", "test")
	for _, command := range root.Commands() {
		if command.Name() == "scan" {
			root.RemoveCommand(command)
		}
	}
	root.AddCommand(newScanCmdWithFactory(factory))
	return root, path
}

func TestScanPreservesPartialReportAndExitCode(t *testing.T) {
	stub := &scannerStub{result: core.ScanResult{Target: "repo", Duration: time.Second,
		AnalysisResult: core.AnalysisResult{
			Findings:    []core.Finding{{ID: "kept", Severity: core.SeverityHigh}},
			Diagnostics: []core.Diagnostic{{Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError, Code: "fixture.failed", Message: "failed"}},
		}}}
	root, path := scanRootForTest(t, func(*config.Config) scanService { return stub })
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", ".", "--config", path, "--diff=HEAD~1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := root.ExecuteContext(ctx)
	if ExitCode(err) != 3 {
		t.Fatalf("exit = %d, err = %v", ExitCode(err), err)
	}
	var got struct {
		Status      string
		Findings    []core.Finding
		Diagnostics []core.Diagnostic
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v: %s", err, stdout.String())
	}
	if got.Status != "partial" || len(got.Findings) != 1 || got.Findings[0].ID != "kept" || len(got.Diagnostics) != 1 {
		t.Fatalf("lost results: %#v", got)
	}
	if stub.ref != "HEAD~1" || stub.ctx != ctx {
		t.Fatal("diff or context did not reach scan service")
	}
	if !strings.Contains(stderr.String(), "fixture.failed") {
		t.Fatal("missing stderr diagnostic")
	}
}

func TestScanRejectsInvalidOptionsBeforeStarting(t *testing.T) {
	for _, args := range [][]string{
		{"--format=typo"}, {"--timeout=0"}, {"--timeout=-1"}, {"--sandbox=unknown"},
		{"--diff="}, {"--quiet", "--verbose"}, {"--unknown"}, {"one", "two"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			called := false
			root, path := scanRootForTest(t, func(*config.Config) scanService { called = true; return &scannerStub{} })
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			root.SetArgs(append([]string{"scan", "--config", path}, args...))
			err := root.Execute()
			if ExitCode(err) != 2 || called {
				t.Fatalf("exit=%d started=%v err=%v", ExitCode(err), called, err)
			}
		})
	}
}

func TestExplicitConfigAndFlagPrecedence(t *testing.T) {
	var received *config.Config
	root, path := scanRootForTest(t, func(cfg *config.Config) scanService { received = cfg; return &scannerStub{} })
	root.SetOut(io.Discard)
	root.SetArgs([]string{"scan", "--config", path, "--format=sarif", "--timeout=7"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if received.Output.Format != "sarif" || received.Scan.Timeout != 7 {
		t.Fatalf("flags not applied: %#v", received)
	}
	root, path = scanRootForTest(t, func(*config.Config) scanService { t.Fatal("scan started with missing config"); return nil })
	root.SetArgs([]string{"scan", "--config", path + ".missing"})
	if err := root.Execute(); ExitCode(err) != 2 {
		t.Fatalf("missing config error = %v", err)
	}
}

type failedOutput struct{ err error }

func (w failedOutput) Write([]byte) (int, error) { return 0, w.err }

func TestScanOutputFailureTakesPrecedenceOverPartialScan(t *testing.T) {
	want := errors.New("disk full")
	root, path := scanRootForTest(t, func(*config.Config) scanService {
		return &scannerStub{result: core.ScanResult{AnalysisResult: core.AnalysisResult{Diagnostics: []core.Diagnostic{{Severity: core.DiagnosticError}}}}}
	})
	root.SetOut(failedOutput{want})
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--config", path})
	err := root.Execute()
	if ExitCode(err) != 4 || !errors.Is(err, want) {
		t.Fatalf("exit=%d err=%v", ExitCode(err), err)
	}
}

func TestQuietKeepsMachineReportsAndFindingsStayAdvisory(t *testing.T) {
	for _, format := range []string{"json", "sarif", "llm", "terminal"} {
		t.Run(format, func(t *testing.T) {
			root, path := scanRootForTest(t, func(*config.Config) scanService {
				return &scannerStub{result: core.ScanResult{AnalysisResult: core.AnalysisResult{Findings: []core.Finding{{ID: "critical", Severity: core.SeverityCritical}}}}}
			})
			var stdout bytes.Buffer
			root.SetOut(&stdout)
			root.SetArgs([]string{"scan", "--config", path, "--quiet", "--format", format})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if (stdout.Len() == 0) != (format == "terminal") {
				t.Fatalf("quiet %s output = %s", format, stdout.String())
			}
		})
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	err := Execute(context.Background(), "test", "test", "test", []string{"not-a-command"}, io.Discard, io.Discard)
	if ExitCode(err) != 2 {
		t.Fatalf("unknown command: %v (exit %d)", err, ExitCode(err))
	}
}

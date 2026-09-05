package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Exercise the shipped executable and a real subprocess boundary without
// installing Semgrep, contacting registries, or requiring provider credentials.
func TestCLIProcessContract(t *testing.T) {
	binDir := t.TempDir()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	sift := filepath.Join(binDir, "sift"+suffix)
	build := func(output, source string) {
		t.Helper()
		command := exec.Command("go", "build", "-o", output, source)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
	}
	build(sift, ".")
	fakeSource := filepath.Join(binDir, "fake_semgrep.go")
	if err := os.WriteFile(fakeSource, []byte(fakeSemgrepProgram), 0o600); err != nil {
		t.Fatal(err)
	}
	build(filepath.Join(binDir, "semgrep"+suffix), fakeSource)
	for _, test := range []struct {
		name, mode, format string
		args               []string
		code, findings     int
		status, diagnostic string
		cleanDiff          bool
	}{
		{name: "complete", mode: "clean", format: "json", status: "complete"},
		{name: "fatal", mode: "fatal", format: "json", code: 3, status: "partial", diagnostic: "semgrep.execution"},
		{name: "malformed", mode: "malformed", format: "json", code: 3, status: "partial", diagnostic: "semgrep.invalid-output"},
		{name: "errors-with-exit-zero", mode: "errors", format: "json", code: 3, status: "partial", diagnostic: "semgrep.error.3"},
		{name: "findings-advisory", mode: "finding", format: "json", findings: 1, status: "complete"},
		{name: "semgrep-findings-exit", mode: "finding-exit", format: "json", findings: 1, status: "complete"},
		{name: "findings-preserved-on-failure", mode: "partial", format: "json", code: 3, findings: 1, status: "partial", diagnostic: "semgrep.execution"},
		{name: "sarif-partial", mode: "partial", format: "sarif", code: 3, findings: 1, status: "partial", diagnostic: "semgrep.execution"},
		{name: "terminal-partial", mode: "fatal", format: "terminal", code: 3, status: "partial", diagnostic: "semgrep.execution"},
		{name: "llm-partial", mode: "fatal", format: "llm", code: 3, status: "partial", diagnostic: "semgrep.execution"},
		{name: "empty-diff-json", mode: "fatal", format: "json", cleanDiff: true, status: "complete"},
		{name: "empty-diff-sarif", mode: "fatal", format: "sarif", cleanDiff: true, status: "complete"},
		{name: "timeout", mode: "timeout", format: "json", args: []string{"--timeout=1"}, code: 3, status: "partial", diagnostic: "semgrep.cancelled"},
		{name: "output-limit", mode: "oversize", format: "json", code: 3, status: "partial", diagnostic: "semgrep.output-limit"},
		{name: "invalid-format", mode: "fatal", format: "invalid", code: 2},
		{name: "missing-config", mode: "fatal", format: "json", args: []string{"--config=missing.toml"}, code: 2},
		{name: "invalid-diff", mode: "fatal", format: "json", args: []string{"--diff=missing"}, cleanDiff: true, code: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := t.TempDir()
			config := filepath.Join(target, "config.toml")
			if err := os.WriteFile(config, []byte("[llm]\nprovider='offline'\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "demo.py"), []byte("print(1)\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"scan", target, "--config", config, "--format", test.format}
			if test.cleanDiff {
				for _, gitArgs := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=Sift Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=", "commit", "-qm", "fixture"}} {
					command := exec.Command("git", append([]string{"-C", target}, gitArgs...)...)
					if output, err := command.CombinedOutput(); err != nil {
						t.Fatalf("git fixture: %v %s", err, output)
					}
				}
				args = append(args, "--diff=HEAD")
			}
			args = append(args, test.args...)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, sift, args...)
			command.Dir = target
			command.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"), "SIFT_LLM_PROVIDER=offline", "SIFT_LLM_API_KEY=", "SIFT_FIXTURE_MODE="+test.mode)
			var stderr strings.Builder
			command.Stderr = &stderr
			output, err := command.Output()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != test.code {
				t.Fatalf("exit=%d want=%d\nstdout=%s\nstderr=%s", code, test.code, output, stderr.String())
			}
			if test.code == 2 {
				if len(output) != 0 || strings.Count(stderr.String(), "error:") != 1 || strings.Contains(stderr.String(), "Usage:") {
					t.Fatalf("invalid error output: stdout=%s stderr=%s", output, stderr.String())
				}
				return
			}
			if test.diagnostic != "" && !strings.Contains(string(output), test.diagnostic) {
				t.Fatalf("missing %s in report: %s", test.diagnostic, output)
			}
			switch test.format {
			case "json":
				var report struct {
					Status      string
					Findings    []json.RawMessage
					Diagnostics []json.RawMessage
				}
				if err := json.Unmarshal(output, &report); err != nil {
					t.Fatalf("JSON: %v: %s", err, output)
				}
				if report.Status != test.status || report.Findings == nil || report.Diagnostics == nil || len(report.Findings) != test.findings {
					t.Fatalf("unexpected JSON: %s", output)
				}
			case "sarif":
				var report struct {
					Version string
					Runs    []struct {
						Results     []json.RawMessage
						Invocations []struct{ ExecutionSuccessful bool }
					}
				}
				if err := json.Unmarshal(output, &report); err != nil {
					t.Fatalf("SARIF: %v: %s", err, output)
				}
				if report.Version != "2.1.0" || len(report.Runs) != 1 || report.Runs[0].Results == nil || len(report.Runs[0].Results) != test.findings || len(report.Runs[0].Invocations) != 1 || report.Runs[0].Invocations[0].ExecutionSuccessful != (test.status == "complete") {
					t.Fatalf("unexpected SARIF: %s", output)
				}
			default:
				if !strings.Contains(string(output), "Scan status: "+test.status) || strings.Contains(string(output), "No issues found") {
					t.Fatalf("misleading text report: %s", output)
				}
			}
			if test.mode == "fatal" && !test.cleanDiff && !strings.Contains(string(output), "fixture subprocess failure") {
				t.Fatal("lost subprocess stderr")
			}
		})
	}
}

const fakeSemgrepProgram = `package main
import("fmt";"os";"time")
func main() {
 mode:=os.Getenv("SIFT_FIXTURE_MODE")
 switch mode {
 case "fatal": fmt.Fprintln(os.Stderr,"fixture subprocess failure"); os.Exit(2)
 case "malformed": fmt.Print("not json"); return
 case "timeout": time.Sleep(4*time.Second)
 case "oversize": os.Stdout.Write(make([]byte,33*1024*1024)); return
 case "errors": fmt.Print("{\"results\":[],\"errors\":[{\"code\":3,\"level\":\"warn\",\"message\":\"fixture parse failure\",\"path\":\"demo.py\"}]}"); return
 }
 if mode=="finding" || mode=="partial" || mode=="finding-exit" {
  fmt.Print("{\"results\":[{\"check_id\":\"fixture.rule\",\"path\":\"demo.py\",\"start\":{\"line\":1,\"col\":1},\"end\":{\"line\":1,\"col\":2},\"extra\":{\"message\":\"fixture finding\",\"severity\":\"ERROR\",\"lines\":\"print(1)\"}}],\"errors\":[]}")
  if mode=="partial" { os.Exit(2) }; if mode=="finding-exit" { os.Exit(1) }; return
 }
 fmt.Print("{\"results\":[],\"errors\":[]}")
}`

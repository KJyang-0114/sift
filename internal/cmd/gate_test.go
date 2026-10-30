package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/policy"
)

func gateFinding(t *testing.T, rule string, severity core.Severity, confidence core.Confidence) core.Finding {
	t.Helper()
	f, err := core.NewFinding(core.FindingInput{
		Source: "semgrep", Rule: rule, Message: rule + " issue", Severity: severity, Category: "security",
		Confidence: confidence, Location: core.Location{Path: "app.py", Line: 3},
		Evidence:    []core.Evidence{{Kind: core.EvidenceCode, Snippet: rule + "(x)"}},
		Remediation: "fix",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func runScan(t *testing.T, stub *scannerStub, args ...string) (int, string, string) {
	t.Helper()
	root, path := scanRootForTest(t, func(*config.Config) scanService { return stub })
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"scan", ".", "--config", path}, args...))
	err := root.Execute()
	return ExitCode(err), stdout.String(), stderr.String()
}

type reportSummary struct {
	Status   string
	Summary  struct{ Total, Active, Suppressed int }
	Findings []core.Finding
}

func decodeReport(t *testing.T, data string) reportSummary {
	t.Helper()
	var report reportSummary
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		t.Fatalf("invalid JSON report: %v\n%s", err, data)
	}
	return report
}

func TestFailOnBlocksAfterWritingReport(t *testing.T) {
	stub := &scannerStub{result: core.ScanResult{Target: "repo", Duration: time.Second, AnalysisResult: core.AnalysisResult{
		Findings: []core.Finding{gateFinding(t, "sql", core.SeverityHigh, core.ConfidenceHigh), gateFinding(t, "info", core.SeverityLow, core.ConfidenceHigh)},
	}}}
	code, stdout, stderr := runScan(t, stub, "--fail-on", "high")
	if code != 1 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if report := decodeReport(t, stdout); len(report.Findings) != 2 {
		t.Fatalf("report not written before gate: %+v", report)
	}
	if !strings.Contains(stderr, "gate: 1 finding(s) at or above high") || !strings.Contains(stderr, "[high] sql app.py:3") {
		t.Fatalf("stderr=%s", stderr)
	}

	if code, _, _ := runScan(t, stub, "--fail-on", "critical"); code != 0 {
		t.Fatalf("below threshold exit=%d", code)
	}
	if code, _, _ := runScan(t, stub); code != 0 {
		t.Fatalf("advisory default exit=%d", code)
	}
}

func TestMinConfidenceNarrowsGate(t *testing.T) {
	stub := &scannerStub{result: core.ScanResult{AnalysisResult: core.AnalysisResult{
		Findings: []core.Finding{gateFinding(t, "guess", core.SeverityCritical, core.ConfidenceLow)},
	}}}
	if code, _, _ := runScan(t, stub, "--fail-on", "high", "--min-confidence", "medium"); code != 0 {
		t.Fatalf("low-confidence finding blocked: exit=%d", code)
	}
}

func TestGateTakesPrecedenceOverPartialScan(t *testing.T) {
	stub := &scannerStub{result: core.ScanResult{AnalysisResult: core.AnalysisResult{
		Findings:    []core.Finding{gateFinding(t, "sql", core.SeverityCritical, core.ConfidenceHigh)},
		Diagnostics: []core.Diagnostic{{Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError, Code: "x.failed", Message: "failed"}},
	}}}
	if code, _, _ := runScan(t, stub, "--fail-on", "high"); code != 1 {
		t.Fatalf("exit=%d want 1", code)
	}
	if code, _, _ := runScan(t, stub); code != 3 {
		t.Fatalf("partial without gate exit=%d want 3", code)
	}
}

func TestWriteBaselineThenBaselineSuppressesOnlyAcceptedFindings(t *testing.T) {
	baselinePath := filepath.Join(t.TempDir(), "sift-baseline.json")
	old := gateFinding(t, "sql", core.SeverityHigh, core.ConfidenceHigh)
	stub := &scannerStub{result: core.ScanResult{AnalysisResult: core.AnalysisResult{Findings: []core.Finding{old}}}}

	code, stdout, stderr := runScan(t, stub, "--write-baseline", baselinePath, "--fail-on", "high")
	if code != 0 || !strings.Contains(stderr, "baseline: wrote 1 finding(s)") {
		t.Fatalf("write-baseline exit=%d stderr=%s", code, stderr)
	}
	if report := decodeReport(t, stdout); report.Summary.Suppressed != 1 || report.Summary.Active != 0 {
		t.Fatalf("new baseline not applied: %+v", report.Summary)
	}

	baseline, err := policy.LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	baseline.Findings[0].Reason = "accepted risk"
	if err := policy.WriteBaseline(baselinePath, baseline); err != nil {
		t.Fatal(err)
	}

	moved := old
	moved.Location.Line = 40
	fresh := gateFinding(t, "cmd", core.SeverityCritical, core.ConfidenceHigh)
	stub.result.Findings = []core.Finding{moved, fresh}
	code, stdout, stderr = runScan(t, stub, "--baseline", baselinePath, "--fail-on", "high")
	if code != 1 || !strings.Contains(stderr, "gate: 1 finding(s)") || !strings.Contains(stderr, "cmd app.py") {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	if report.Summary.Total != 2 || report.Summary.Suppressed != 1 || report.Summary.Active != 1 {
		t.Fatalf("summary=%+v", report.Summary)
	}
	if !report.Findings[0].Suppression.Suppressed || report.Findings[0].Suppression.Reason != "baseline: accepted risk" {
		t.Fatalf("suppression=%+v", report.Findings[0].Suppression)
	}

	// Refreshing keeps hand-written reasons for findings that remain.
	if code, _, _ := runScan(t, stub, "--baseline", baselinePath, "--write-baseline", baselinePath); code != 0 {
		t.Fatalf("refresh exit=%d", code)
	}
	refreshed, err := policy.LoadBaseline(baselinePath)
	if err != nil || len(refreshed.Findings) != 2 {
		t.Fatalf("refreshed=%+v err=%v", refreshed, err)
	}
	for _, entry := range refreshed.Findings {
		if entry.Rule == "sql" && entry.Reason != "accepted risk" {
			t.Fatalf("reason lost: %+v", entry)
		}
	}
}

func TestOutputWritesReportFileAndTerminalSummary(t *testing.T) {
	dir := t.TempDir()
	stub := &scannerStub{result: core.ScanResult{Target: "repo", AnalysisResult: core.AnalysisResult{
		Findings:    []core.Finding{gateFinding(t, "sql", core.SeverityHigh, core.ConfidenceHigh)},
		Diagnostics: []core.Diagnostic{{Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticWarning, Code: "x.warn", Message: "careful"}},
	}}}
	sarif := filepath.Join(dir, "results.sarif")
	code, stdout, stderr := runScan(t, stub, "--format", "sarif", "--output", sarif, "--fail-on", "high")
	if code != 1 {
		t.Fatalf("exit=%d", code)
	}
	data, err := os.ReadFile(sarif)
	if err != nil || !strings.Contains(string(data), `"version": "2.1.0"`) {
		t.Fatalf("sarif file=%s err=%v", data, err)
	}
	if !strings.Contains(stdout, "Sift Scan Report") || strings.Contains(stdout, `"version": "2.1.0"`) {
		t.Fatalf("stdout should be the terminal report: %s", stdout)
	}
	if strings.Contains(stderr, "x.warn") {
		t.Fatalf("diagnostics duplicated on stderr: %s", stderr)
	}

	code, stdout, _ = runScan(t, stub, "--format", "json", "--output", filepath.Join(dir, "r.json"), "--quiet")
	if code != 0 || stdout != "" {
		t.Fatalf("quiet output exit=%d stdout=%q", code, stdout)
	}

	code, _, _ = runScan(t, stub, "--output", filepath.Join(dir, "missing", "r.json"))
	if code != 4 {
		t.Fatalf("unwritable output exit=%d want 4", code)
	}
}

func TestInvalidGateOptionsAreUsageErrors(t *testing.T) {
	stub := &scannerStub{}
	for _, args := range [][]string{
		{"--fail-on", "severe"},
		{"--min-confidence", "certain"},
		{"--baseline", filepath.Join(t.TempDir(), "missing.json")},
	} {
		if code, _, _ := runScan(t, stub, args...); code != 2 {
			t.Errorf("%v exit=%d want 2", args, code)
		}
	}
}

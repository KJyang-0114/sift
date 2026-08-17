package core

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanRequestDefensivelyCopiesAndNormalizesTargets(t *testing.T) {
	root := t.TempDir()
	targets := []string{".", `internal\\core\\finding.go`, "fixtures/name,with,commas.go"}
	request, err := NewScanRequest(root, targets)
	if err != nil {
		t.Fatalf("NewScanRequest: %v", err)
	}

	targets[1] = "mutated.go"
	got := request.Targets()
	want := []string{".", "internal/core/finding.go", "fixtures/name,with,commas.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Targets = %#v, want %#v", got, want)
	}

	got[0] = "also-mutated.go"
	if request.Targets()[0] != "." {
		t.Fatal("Targets returned internal mutable storage")
	}
	if request.Root() != filepath.Clean(root) {
		t.Fatalf("Root = %q, want %q", request.Root(), filepath.Clean(root))
	}

	absTargets := request.AbsoluteTargets()
	if absTargets[1] != filepath.Join(root, "internal", "core", "finding.go") {
		t.Fatalf("AbsoluteTargets[1] = %q", absTargets[1])
	}
}

func TestNewScanRequestRejectsUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name    string
		root    string
		targets []string
	}{
		{name: "missing root", targets: []string{"."}},
		{name: "relative root", root: "relative", targets: []string{"."}},
		{name: "missing targets", root: root},
		{name: "empty target", root: root, targets: []string{""}},
		{name: "absolute unix target", root: root, targets: []string{"/tmp/outside.go"}},
		{name: "absolute windows target", root: root, targets: []string{`C:\\outside.go`}},
		{name: "escaping target", root: root, targets: []string{"../outside.go"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewScanRequest(tt.root, tt.targets); err == nil {
				t.Fatal("NewScanRequest succeeded, want error")
			}
		})
	}
}

func TestScanRequestRelativePathRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	request, err := NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}

	inside := filepath.Join(root, "src", "app.go")
	got, err := request.RelativePath(inside)
	if err != nil {
		t.Fatalf("RelativePath inside root: %v", err)
	}
	if got != "src/app.go" {
		t.Fatalf("RelativePath = %q, want src/app.go", got)
	}

	if _, err := request.RelativePath(filepath.Join(filepath.Dir(root), "outside.go")); err == nil {
		t.Fatal("RelativePath accepted a path outside the root")
	}
}

func TestDiagnosticEnums(t *testing.T) {
	for _, kind := range []DiagnosticKind{
		DiagnosticConfiguration,
		DiagnosticPolicy,
		DiagnosticTarget,
		DiagnosticAnalyzer,
		DiagnosticIntegration,
		DiagnosticInternal,
	} {
		if !kind.Valid() {
			t.Fatalf("diagnostic kind %q is invalid", kind)
		}
	}
	if DiagnosticKind("finding").Valid() {
		t.Fatal("unknown diagnostic kind is valid")
	}

	for _, severity := range []DiagnosticSeverity{DiagnosticInfo, DiagnosticWarning, DiagnosticError} {
		if !severity.Valid() {
			t.Fatalf("diagnostic severity %q is invalid", severity)
		}
	}
	if DiagnosticSeverity("fatal").Valid() {
		t.Fatal("unknown diagnostic severity is valid")
	}
}

type analyzerContractStub struct{}

func (analyzerContractStub) Name() string { return "stub" }

func (analyzerContractStub) Analyze(context.Context, ScanRequest) AnalysisResult {
	return AnalysisResult{
		Findings:    []Finding{},
		Diagnostics: []Diagnostic{},
	}
}

func TestAnalyzerContractCanReturnFindingsAndDiagnostics(t *testing.T) {
	var analyzer Analyzer = analyzerContractStub{}
	request, err := NewScanRequest(t.TempDir(), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	result := analyzer.Analyze(context.Background(), request)
	if result.Findings == nil || result.Diagnostics == nil {
		t.Fatal("analyzer result collections must be non-nil")
	}
}

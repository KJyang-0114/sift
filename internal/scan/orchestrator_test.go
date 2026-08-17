package scan

import (
	"context"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

type analyzerStub struct {
	name    string
	analyze func(context.Context, core.ScanRequest) core.AnalysisResult
}

func (stub analyzerStub) Name() string { return stub.name }

func (stub analyzerStub) Analyze(ctx context.Context, request core.ScanRequest) core.AnalysisResult {
	return stub.analyze(ctx, request)
}

func TestRunAnalyzersPreservesOrderTargetsAndDiagnostics(t *testing.T) {
	request, err := core.NewScanRequest(t.TempDir(), []string{"first.go", "name,with,commas.go"})
	if err != nil {
		t.Fatal(err)
	}
	wantTargets := request.Targets()
	analyzers := []core.Analyzer{
		analyzerStub{name: "first", analyze: func(_ context.Context, got core.ScanRequest) core.AnalysisResult {
			if targets := got.Targets(); len(targets) != 2 || targets[1] != wantTargets[1] {
				t.Fatalf("targets were transported incorrectly: %#v", targets)
			}
			return core.AnalysisResult{
				Findings: []core.Finding{{ID: "first"}},
				Diagnostics: []core.Diagnostic{{
					Kind: core.DiagnosticIntegration, Severity: core.DiagnosticWarning,
					Code: "partial", Message: "partial",
				}},
			}
		}},
		analyzerStub{name: "second", analyze: func(context.Context, core.ScanRequest) core.AnalysisResult {
			return core.AnalysisResult{Findings: []core.Finding{{ID: "second"}}, Diagnostics: []core.Diagnostic{}}
		}},
	}
	orchestrator := &Orchestrator{pool: NewWorkerPool(2, time.Second)}

	results := orchestrator.runAnalyzers(context.Background(), analyzers, request)
	if len(results) != 2 || results[0].Analyzer != "first" || results[1].Analyzer != "second" {
		t.Fatalf("results lost input order: %#v", results)
	}
	if len(results[0].Findings) != 1 || len(results[0].Diagnostics) != 1 {
		t.Fatalf("partial result was not preserved: %#v", results[0])
	}
}

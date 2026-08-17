package scan

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

func TestWorkerPoolLimitsConcurrencyAndPreservesOrder(t *testing.T) {
	pool := NewWorkerPool(2, time.Second)
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	var active atomic.Int32
	var maximum atomic.Int32
	jobs := make([]Job, 8)
	for i := range jobs {
		name := strconv.Itoa(i)
		jobs[i] = Job{Name: name, Analyze: func(context.Context) core.AnalysisResult {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			return core.AnalysisResult{Findings: []core.Finding{{ID: name}}, Diagnostics: []core.Diagnostic{}}
		}}
	}

	done := make(chan []BatchResult, 1)
	go func() { done <- pool.Run(context.Background(), jobs) }()
	<-started
	<-started
	close(release)
	results := <-done

	if maximum.Load() > 2 {
		t.Fatalf("observed %d concurrent jobs, want at most 2", maximum.Load())
	}
	for i, result := range results {
		want := strconv.Itoa(i)
		if result.Name != want || len(result.Findings) != 1 || result.Findings[0].ID != want {
			t.Fatalf("result %d = %#v, want job %q in input order", i, result, want)
		}
	}
}

func TestWorkerPoolPreservesPartialResultsAndCountsErrorDiagnostics(t *testing.T) {
	pool := NewWorkerPool(1, time.Second)
	results := pool.Run(context.Background(), []Job{
		{Name: "ok", Analyze: func(context.Context) core.AnalysisResult {
			return core.AnalysisResult{Findings: []core.Finding{{ID: "kept"}}, Diagnostics: []core.Diagnostic{}}
		}},
		{Name: "partial", Analyze: func(context.Context) core.AnalysisResult {
			return core.AnalysisResult{
				Findings: []core.Finding{{ID: "partial"}},
				Diagnostics: []core.Diagnostic{{
					Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
					Code: "test.failure", Message: "failed",
				}},
			}
		}},
	})

	if len(results[1].Findings) != 1 || len(results[1].Diagnostics) != 1 {
		t.Fatalf("partial result was discarded: %#v", results[1])
	}
	got := pool.Stats()
	for _, fragment := range []string{"workers=1", "jobs=2", "completed=2", "failed=1"} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("Stats() = %q, want fragment %q", got, fragment)
		}
	}
}

func TestWorkerPoolTimeoutBecomesTypedDiagnostic(t *testing.T) {
	pool := NewWorkerPool(1, 20*time.Millisecond)
	results := pool.Run(context.Background(), []Job{{
		Name: "slow",
		Analyze: func(ctx context.Context) core.AnalysisResult {
			<-ctx.Done()
			return core.AnalysisResult{Findings: []core.Finding{}, Diagnostics: []core.Diagnostic{}}
		},
	}})

	if len(results) != 1 || len(results[0].Diagnostics) != 1 {
		t.Fatalf("results = %#v", results)
	}
	diagnostic := results[0].Diagnostics[0]
	if diagnostic.Code != "analyzer.timeout" || diagnostic.Kind != core.DiagnosticAnalyzer {
		t.Fatalf("unexpected timeout diagnostic: %#v", diagnostic)
	}
}

func TestScanWithCacheAnalyzesChangedAndUncertainFiles(t *testing.T) {
	pool := NewWorkerPool(2, time.Second)
	changed := map[string]bool{"changed.go": true, "unchanged.go": false}
	var mu sync.Mutex
	var analyzed []string
	marked := map[string]int{}

	result := pool.ScanWithCache(
		context.Background(),
		[]string{"unchanged.go", "changed.go", "uncertain.go", "broken.go"},
		func(_ context.Context, path string) core.AnalysisResult {
			mu.Lock()
			analyzed = append(analyzed, path)
			mu.Unlock()
			if path == "broken.go" {
				return core.AnalysisResult{
					Findings: []core.Finding{},
					Diagnostics: []core.Diagnostic{{
						Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
						Code: "analysis.failed", Message: "failed",
					}},
				}
			}
			return core.AnalysisResult{Findings: []core.Finding{{ID: path}}, Diagnostics: []core.Diagnostic{}}
		},
		func(path string) (bool, error) {
			if path == "uncertain.go" || path == "broken.go" {
				return false, errors.New("cache unavailable")
			}
			return changed[path], nil
		},
		func(path string, count int) error {
			mu.Lock()
			marked[path] = count
			mu.Unlock()
			return nil
		},
	)

	mu.Lock()
	defer mu.Unlock()
	if len(analyzed) != 3 {
		t.Fatalf("analyzed files = %#v, want three changed/uncertain files", analyzed)
	}
	if len(result.Findings) != 2 || len(result.Diagnostics) != 1 {
		t.Fatalf("result = %#v, want two findings and one diagnostic", result)
	}
	if marked["changed.go"] != 1 || marked["uncertain.go"] != 1 {
		t.Fatalf("marked = %#v, want successful files recorded", marked)
	}
	if _, exists := marked["broken.go"]; exists {
		t.Fatalf("failed file was marked scanned: %#v", marked)
	}
}

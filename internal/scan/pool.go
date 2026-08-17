package scan

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

// WorkerPool provides controlled concurrent analysis execution.
type WorkerPool struct {
	maxWorkers int
	timeout    time.Duration
	semaphore  chan struct{}
	mu         sync.Mutex
	totalJobs  int
	completed  int
	failed     int
}

// NewWorkerPool creates a Worker Pool.
func NewWorkerPool(maxWorkers int, timeout time.Duration) *WorkerPool {
	if maxWorkers <= 0 {
		maxWorkers = 4
	}
	return &WorkerPool{
		maxWorkers: maxWorkers,
		timeout:    timeout,
		semaphore:  make(chan struct{}, maxWorkers),
	}
}

// Job represents an analysis task.
type Job struct {
	Name    string
	Analyze func(context.Context) core.AnalysisResult
}

// BatchResult represents one scheduled analyzer result.
type BatchResult struct {
	Name        string            `json:"name"`
	Findings    []core.Finding    `json:"findings"`
	Diagnostics []core.Diagnostic `json:"diagnostics"`
	Duration    time.Duration     `json:"duration"`
}

// Run executes analysis jobs in input order with bounded concurrency.
func (pool *WorkerPool) Run(ctx context.Context, jobs []Job) []BatchResult {
	results := make([]BatchResult, len(jobs))
	var group sync.WaitGroup

	for index, job := range jobs {
		group.Add(1)
		go func(resultIndex int, scheduled Job) {
			defer group.Done()
			start := time.Now()
			analysis := core.AnalysisResult{Findings: []core.Finding{}, Diagnostics: []core.Diagnostic{}}

			select {
			case pool.semaphore <- struct{}{}:
				defer func() { <-pool.semaphore }()
			case <-ctx.Done():
				analysis.Diagnostics = append(analysis.Diagnostics, contextDiagnostic(scheduled.Name, ctx.Err()))
				pool.recordResult(analysis.Diagnostics)
				results[resultIndex] = batchResult(scheduled.Name, analysis, time.Since(start))
				return
			}

			pool.mu.Lock()
			pool.totalJobs++
			pool.mu.Unlock()

			jobCtx := ctx
			cancel := func() {}
			if pool.timeout > 0 {
				jobCtx, cancel = context.WithTimeout(ctx, pool.timeout)
			}
			analysis = scheduled.Analyze(jobCtx)
			jobErr := jobCtx.Err()
			cancel()
			if analysis.Findings == nil {
				analysis.Findings = []core.Finding{}
			}
			if analysis.Diagnostics == nil {
				analysis.Diagnostics = []core.Diagnostic{}
			}
			if jobErr != nil {
				analysis.Diagnostics = append(analysis.Diagnostics, contextDiagnostic(scheduled.Name, jobErr))
			}

			pool.recordResult(analysis.Diagnostics)
			results[resultIndex] = batchResult(scheduled.Name, analysis, time.Since(start))
		}(index, job)
	}

	group.Wait()
	return results
}

func batchResult(name string, analysis core.AnalysisResult, duration time.Duration) BatchResult {
	return BatchResult{
		Name: name, Findings: analysis.Findings, Diagnostics: analysis.Diagnostics, Duration: duration,
	}
}

func contextDiagnostic(source string, err error) core.Diagnostic {
	code := "analyzer.cancelled"
	if errors.Is(err, context.DeadlineExceeded) {
		code = "analyzer.timeout"
	}
	return core.Diagnostic{
		Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
		Code: code, Source: source, Message: err.Error(), Cause: err,
	}
}

func (pool *WorkerPool) recordResult(diagnostics []core.Diagnostic) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.completed++
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == core.DiagnosticError {
			pool.failed++
			return
		}
	}
}

// Stats returns execution statistics.
func (pool *WorkerPool) Stats() string {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return fmt.Sprintf("workers=%d jobs=%d completed=%d failed=%d",
		pool.maxWorkers, pool.totalJobs, pool.completed, pool.failed)
}

// ScanWithCache performs incremental scanning using the v2 result contract.
func (pool *WorkerPool) ScanWithCache(
	ctx context.Context,
	files []string,
	analyze func(context.Context, string) core.AnalysisResult,
	isChanged func(string) (bool, error),
	markScanned func(string, int) error,
) core.AnalysisResult {
	changedFiles := make([]string, 0, len(files))
	skippedCount := 0
	for _, file := range files {
		changed, err := isChanged(file)
		if err != nil || changed {
			changedFiles = append(changedFiles, file)
		} else {
			skippedCount++
		}
	}

	if skippedCount > 0 {
		fmt.Printf("  ⚡ incremental scan: skipped %d unchanged file(s), scanning %d\n", skippedCount, len(changedFiles))
	}

	jobs := make([]Job, 0, len(changedFiles))
	for _, file := range changedFiles {
		file := file
		jobs = append(jobs, Job{
			Name: file,
			Analyze: func(jobCtx context.Context) core.AnalysisResult {
				result := analyze(jobCtx, file)
				if !hasErrorDiagnostic(result.Diagnostics) {
					if err := markScanned(file, len(result.Findings)); err != nil {
						result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
							Kind: core.DiagnosticIntegration, Severity: core.DiagnosticWarning,
							Code: "cache.mark-failed", Source: "file-cache", Message: err.Error(), Cause: err,
						})
					}
				}
				return result
			},
		})
	}

	analysis := core.AnalysisResult{Findings: []core.Finding{}, Diagnostics: []core.Diagnostic{}}
	for _, result := range pool.Run(ctx, jobs) {
		analysis.Findings = append(analysis.Findings, result.Findings...)
		analysis.Diagnostics = append(analysis.Diagnostics, result.Diagnostics...)
	}
	return analysis
}

func hasErrorDiagnostic(diagnostics []core.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == core.DiagnosticError {
			return true
		}
	}
	return false
}

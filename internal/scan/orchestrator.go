package scan

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/agent"
	"github.com/KJyang-0114/sift/internal/cache"
	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/report"
	"github.com/KJyang-0114/sift/internal/static"
	"github.com/KJyang-0114/sift/internal/store"
)

// Orchestrator coordinates all analyzers and executes the fully automated scan workflow.
type Orchestrator struct {
	cfg              *config.Config
	staticAnalyzers  []core.Analyzer
	dynamicAnalyzers []core.Analyzer
	reporters        *report.Engine
	lastFindings     []core.Finding
	lastDiagnostics  []core.Diagnostic
	pool             *WorkerPool
	diffRef          string // non-empty when diff mode is active
	initErr          error
}

// SetDiffMode enables diff mode with the given git ref, scanning only git-changed files.
// The ref can be "HEAD" (unstaged+staged), "HEAD~1" (changes since last commit), or a branch name.
func (o *Orchestrator) SetDiffMode(ref string) {
	o.diffRef = ref
}

// NewOrchestrator creates a scan orchestrator.
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	rulesDir := findRulesDir()

	semgrep := static.NewSemgrepAnalyzer(rulesDir, time.Duration(cfg.Scan.Timeout)*time.Second)
	pkgVerifier := agent.NewPackageVerifier()

	staticAnalyzers := []core.Analyzer{semgrep, pkgVerifier}
	dynamicAnalyzers := []core.Analyzer{}
	var initErr error

	// If LLM is configured, add semantic analysis and test generation
	if cfg.LLM.Provider != config.ProviderOffline && cfg.LLM.APIKey != "" {
		if sa, err := agent.NewSemanticAnalyzer(cfg); err == nil {
			staticAnalyzers = append(staticAnalyzers, sa)
		} else {
			initErr = fmt.Errorf("initialize semantic analyzer: %w", err)
		}
		if tg, err := agent.NewTestGenerator(cfg); err == nil {
			dynamicAnalyzers = append(dynamicAnalyzers, tg)
		} else if initErr == nil {
			initErr = fmt.Errorf("initialize test generator: %w", err)
		}
	}

	// Enterprise: Worker Pool (controls concurrency, avoids API rate limits)
	pool := NewWorkerPool(cfg.Scan.Concurrency, time.Duration(cfg.Scan.Timeout)*time.Second)

	return &Orchestrator{
		cfg:              cfg,
		staticAnalyzers:  staticAnalyzers,
		dynamicAnalyzers: dynamicAnalyzers,
		reporters:        report.NewEngine(cfg),
		pool:             pool,
		initErr:          initErr,
	}
}

// Run executes the full scan workflow.
func (o *Orchestrator) Run(target string, format string) error {
	return o.RunContext(context.Background(), target, format)
}

// RunContext executes the scan and renders a report to standard output.
func (o *Orchestrator) RunContext(ctx context.Context, target string, format string) error {
	return o.RunTo(ctx, target, format, os.Stdout)
}

// RunTo renders partial results before returning their operational error.
func (o *Orchestrator) RunTo(ctx context.Context, target, format string, out io.Writer) error {
	if !report.ValidFormat(format) {
		return &core.OperationError{Kind: core.DiagnosticConfiguration, Err: fmt.Errorf("unsupported output format %q", format)}
	}
	result, err := o.Scan(ctx, target)
	if err != nil {
		return err
	}
	if err := o.reporters.Render(out, result.Findings, result.Diagnostics, result.Target, result.Duration, format); err != nil {
		return &core.OperationError{Kind: core.DiagnosticInternal, Err: fmt.Errorf("write %s report: %w", format, err)}
	}
	return result.Err()
}

// Scan collects results without rendering output or terminating the process.
func (o *Orchestrator) Scan(ctx context.Context, target string) (core.ScanResult, error) {
	start := time.Now()
	o.lastFindings = nil
	o.lastDiagnostics = nil
	result := core.ScanResult{AnalysisResult: core.AnalysisResult{Findings: []core.Finding{}, Diagnostics: []core.Diagnostic{}}}
	if o.initErr != nil {
		return result, &core.OperationError{Kind: core.DiagnosticConfiguration, Err: o.initErr}
	}
	absolute, err := filepath.Abs(target)
	if err != nil {
		return result, &core.OperationError{Kind: core.DiagnosticTarget, Err: fmt.Errorf("resolve target: %w", err)}
	}
	if _, err := os.Stat(absolute); err != nil {
		return result, &core.OperationError{Kind: core.DiagnosticTarget, Err: fmt.Errorf("read target: %w", err)}
	}
	root, targets := scanRootAndTargets(absolute)
	result.Target = root
	if o.diffRef != "" {
		changed, err := gitChangedFiles(ctx, root, o.diffRef, targets)
		if err != nil {
			return result, &core.OperationError{Kind: core.DiagnosticTarget, Err: fmt.Errorf("resolve git diff %q: %w", o.diffRef, err)}
		}
		targets = changed
	}
	if len(targets) > 0 {
		request, err := core.NewScanRequest(root, targets)
		if err != nil {
			return result, &core.OperationError{Kind: core.DiagnosticTarget, Err: fmt.Errorf("create scan request: %w", err)}
		}
		for _, analyzers := range [][]core.Analyzer{o.staticAnalyzers, o.dynamicAnalyzers} {
			for _, run := range o.runAnalyzers(ctx, analyzers, request) {
				result.Findings = append(result.Findings, run.Findings...)
				result.Diagnostics = append(result.Diagnostics, run.Diagnostics...)
			}
		}
	}
	// Cancellation must remain visible even when no analyzer job was scheduled.
	if ctx.Err() != nil && !result.HasErrors() {
		result.Diagnostics = append(result.Diagnostics, contextDiagnostic("scan", ctx.Err()))
	}
	result.Duration = time.Since(start)
	if len(targets) > 0 {
		persistScan(&result)
	}
	o.lastFindings = append([]core.Finding{}, result.Findings...)
	o.lastDiagnostics = append([]core.Diagnostic{}, result.Diagnostics...)
	return result, nil
}

// Persistence failures do not invalidate completed analysis, but remain visible.
func persistScan(result *core.ScanResult) {
	warn := func(code string, err error) {
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
				Kind: core.DiagnosticIntegration, Severity: core.DiagnosticWarning,
				Code: code, Source: "scan-history", Message: err.Error(), Cause: err,
			})
		}
	}
	database, err := store.NewStore(result.Target)
	if err != nil {
		warn("store.open", err)
	} else {
		_, err = database.SaveScan(result.Target, result.Duration, result.Findings, 0)
		warn("store.save", err)
		warn("store.close", database.Close())
	}
	fileCache, err := cache.NewFileCache(result.Target)
	if err != nil {
		warn("cache.open", err)
	} else {
		warn("cache.save", fileCache.Save())
	}
}

// AnalyzerRunResult records one scheduled analyzer invocation.
type AnalyzerRunResult struct {
	Analyzer    string
	Findings    []core.Finding
	Diagnostics []core.Diagnostic
	Duration    time.Duration
}

// runAnalyzers runs all analyzers through the context-aware worker pool.
func (o *Orchestrator) runAnalyzers(ctx context.Context, analyzers []core.Analyzer, request core.ScanRequest) []AnalyzerRunResult {
	jobs := make([]Job, 0, len(analyzers))
	for _, analyzer := range analyzers {
		analyzer := analyzer
		jobs = append(jobs, Job{
			Name: analyzer.Name(),
			Analyze: func(jobCtx context.Context) core.AnalysisResult {
				return analyzer.Analyze(jobCtx, request)
			},
		})
	}
	pool := o.pool
	if pool == nil {
		pool = NewWorkerPool(4, 0)
	}
	batch := pool.Run(ctx, jobs)
	results := make([]AnalyzerRunResult, len(batch))
	for i, result := range batch {
		results[i] = AnalyzerRunResult{
			Analyzer: result.Name, Findings: result.Findings,
			Diagnostics: result.Diagnostics, Duration: result.Duration,
		}
	}
	return results
}

// findRulesDir locates the rules directory.
func findRulesDir() string {
	if cwd, err := os.Getwd(); err == nil {
		dir := filepath.Join(cwd, "internal", "static", "rules")
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return "internal/static/rules"
}

// LastFindings returns all findings from the most recent scan.
func (o *Orchestrator) LastFindings() []core.Finding {
	findings := make([]core.Finding, len(o.lastFindings))
	copy(findings, o.lastFindings)
	return findings
}

// LastDiagnostics returns diagnostics from the most recent scan.
func (o *Orchestrator) LastDiagnostics() []core.Diagnostic {
	diagnostics := make([]core.Diagnostic, len(o.lastDiagnostics))
	copy(diagnostics, o.lastDiagnostics)
	return diagnostics
}

// gitChangedFiles returns existing tracked paths changed against the selected commit.
// NUL delimiters preserve filenames; --relative keeps paths inside the target root.
func gitChangedFiles(ctx context.Context, repoPath, ref string, targets []string) ([]string, error) {
	revision, err := exec.CommandContext(ctx, "git", "-C", repoPath, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}").Output()
	if err != nil {
		return nil, err
	}
	args := []string{"-C", repoPath, "diff", "--relative", "--name-only", "-z", "--diff-filter=d", strings.TrimSpace(string(revision)), "--"}
	args = append(args, targets...)
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return nil, err
	}
	files := []string{}
	for _, file := range strings.Split(string(out), "\x00") {
		if file != "" {
			files = append(files, filepath.ToSlash(file))
		}
	}
	return files, nil
}

func absTarget(target string) string {
	if abs, err := filepath.Abs(target); err == nil {
		return abs
	}
	return target
}

func scanRootAndTargets(target string) (string, []string) {
	absolute := absTarget(target)
	if info, err := os.Stat(absolute); err == nil && !info.IsDir() {
		return filepath.Dir(absolute), []string{filepath.Base(absolute)}
	}
	return absolute, []string{"."}
}

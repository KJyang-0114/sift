package scan

import (
	"context"
	"fmt"
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
	fileCache        *cache.FileCache
	dbStore          *store.Store
	pool             *WorkerPool
	diffRef          string // non-empty when diff mode is active
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

	// If LLM is configured, add semantic analysis and test generation
	if cfg.LLM.Provider != config.ProviderOffline && cfg.LLM.APIKey != "" {
		if sa, err := agent.NewSemanticAnalyzer(cfg); err == nil {
			staticAnalyzers = append(staticAnalyzers, sa)
		}
		if tg, err := agent.NewTestGenerator(cfg); err == nil {
			dynamicAnalyzers = append(dynamicAnalyzers, tg)
		}
	}

	// Enterprise: initialize cache (incremental scan)
	fc, _ := cache.NewFileCache(".")

	// Enterprise: initialize SQLite persistence
	dbStore, _ := store.NewStore(".")

	// Enterprise: Worker Pool (controls concurrency, avoids API rate limits)
	pool := NewWorkerPool(cfg.Scan.Concurrency, time.Duration(cfg.Scan.Timeout)*time.Second)

	return &Orchestrator{
		cfg:              cfg,
		staticAnalyzers:  staticAnalyzers,
		dynamicAnalyzers: dynamicAnalyzers,
		reporters:        report.NewEngine(cfg),
		fileCache:        fc,
		dbStore:          dbStore,
		pool:             pool,
	}
}

// Run executes the full scan workflow.
func (o *Orchestrator) Run(target string, format string) error {
	return o.RunContext(context.Background(), target, format)
}

// RunContext executes the full scan workflow with cancellation.
func (o *Orchestrator) RunContext(ctx context.Context, target string, format string) error {
	root, targets := scanRootAndTargets(target)

	verbose := format != "json" && format != "sarif"

	// diff mode: only scan git-changed files
	if o.diffRef != "" {
		changed, err := gitChangedFiles(root, o.diffRef)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  unable to get git diff: %v\n", err)
			// fall through to full scan
		} else if len(changed) == 0 {
			if verbose {
				fmt.Println("  ✅ no changed files to scan")
			}
			return nil
		} else {
			if verbose {
				fmt.Printf("  📋 diff mode (ref=%s): %d changed file(s)\n", o.diffRef, len(changed))
			}
			targets = changed
		}
	}
	request, err := core.NewScanRequest(root, targets)
	if err != nil {
		return fmt.Errorf("create scan request: %w", err)
	}

	if verbose {
		fmt.Printf("  🔍 Sift scanning: %s\n\n", root)
	}

	start := time.Now()
	allFindings := []core.Finding{}
	allDiagnostics := []core.Diagnostic{}

	// Phase 1: Static Analysis (Semgrep + package verification + LLM semantic analysis)
	if verbose {
		fmt.Println("  ── Phase 1: Static Analysis ──")
	}
	results := o.runAnalyzers(ctx, o.staticAnalyzers, request)
	for _, r := range results {
		for _, diagnostic := range r.Diagnostics {
			fmt.Fprintf(os.Stderr, "  ⚠️  %s [%s]: %s\n", r.Analyzer, diagnostic.Code, diagnostic.Message)
		}
		allDiagnostics = append(allDiagnostics, r.Diagnostics...)
		if verbose {
			fmt.Printf("  ✅ %s: %d issue(s)\n", r.Analyzer, len(r.Findings))
		}
		allFindings = append(allFindings, r.Findings...)
	}

	// Phase 2: Dynamic Testing (sandbox execution, enabled only when LLM is available)
	if len(o.dynamicAnalyzers) > 0 {
		if verbose {
			fmt.Println()
			fmt.Println("  ── Phase 2: Dynamic Testing ──")
		}
		dynResults := o.runAnalyzers(ctx, o.dynamicAnalyzers, request)
		for _, r := range dynResults {
			for _, diagnostic := range r.Diagnostics {
				fmt.Fprintf(os.Stderr, "  ⚠️  %s [%s]: %s\n", r.Analyzer, diagnostic.Code, diagnostic.Message)
			}
			allDiagnostics = append(allDiagnostics, r.Diagnostics...)
			if verbose {
				fmt.Printf("  ✅ %s: %d issue(s)\n", r.Analyzer, len(r.Findings))
			}
			allFindings = append(allFindings, r.Findings...)
		}
	}

	if verbose {
		fmt.Println()
	}

	// Output report
	o.lastFindings = allFindings
	o.lastDiagnostics = allDiagnostics
	legacyFindings := toLegacyFindings(allFindings)

	// Enterprise: persist to SQLite + cache
	if o.dbStore != nil {
		o.dbStore.SaveScan(root, time.Since(start), legacyFindings, 0)
	}
	if o.fileCache != nil {
		o.fileCache.Save()
	}

	o.reporters.Render(legacyFindings, root, time.Since(start), format)

	return nil
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

// gitChangedFiles returns the list of files changed relative to the given git ref.
// If ref is "HEAD", returns both unstaged and staged changes vs HEAD.
func gitChangedFiles(repoPath, ref string) ([]string, error) {
	var out []byte
	var err error

	if ref == "HEAD" {
		// For HEAD: combine unstaged + staged diff
		out, err = exec.Command("git", "-C", repoPath, "diff", "--name-only", "HEAD", "--", ".").Output()
		if err != nil {
			return nil, err
		}
		stagedOut, stagedErr := exec.Command("git", "-C", repoPath, "diff", "--name-only", "--staged", "--", ".").Output()
		if stagedErr == nil {
			if len(out) > 0 && len(stagedOut) > 0 {
				out = append(out, '\n')
				out = append(out, stagedOut...)
			} else if len(stagedOut) > 0 {
				out = stagedOut
			}
		}
	} else {
		cmd := exec.Command("git", "-C", repoPath, "diff", "--name-only", ref, "--", ".")
		out, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f = strings.TrimSpace(f)
		if f != "" {
			files = append(files, filepath.ToSlash(f))
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

// toLegacyFindings is removed in Task 6 when reporters and persistence consume v2 directly.
func toLegacyFindings(findings []core.Finding) []static.Finding {
	legacy := make([]static.Finding, 0, len(findings))
	for _, finding := range findings {
		code := ""
		if len(finding.Evidence) > 0 {
			code = finding.Evidence[0].Snippet
		}
		legacy = append(legacy, static.Finding{
			ID: finding.ID, Rule: finding.Rule, Message: finding.Message,
			Severity: static.Severity(finding.Severity), Category: finding.Category,
			File: finding.Location.Path, Line: finding.Location.Line, Column: finding.Location.Column,
			Code: code, CWE: finding.CWE, OWASP: finding.OWASP,
		})
	}
	return legacy
}

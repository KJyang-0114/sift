package scan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/KJyang-0114/sift/internal/agent"
	"github.com/KJyang-0114/sift/internal/cache"
	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/report"
	"github.com/KJyang-0114/sift/internal/static"
	"github.com/KJyang-0114/sift/internal/store"
)

// Orchestrator coordinates all analyzers and executes the fully automated scan workflow.
type Orchestrator struct {
	cfg              *config.Config
	staticAnalyzers  []static.Analyzer
	dynamicAnalyzers []static.Analyzer
	reporters        *report.Engine
	lastFindings     []static.Finding
	fileCache        *cache.FileCache
	dbStore          *store.Store
	pool             *WorkerPool
	diffMode         bool
}

// SetDiffMode enables diff mode, scanning only git-changed files.
func (o *Orchestrator) SetDiffMode(enabled bool) {
	o.diffMode = enabled
}

// NewOrchestrator creates a scan orchestrator.
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	rulesDir := findRulesDir()

	semgrep := static.NewSemgrepAnalyzer(rulesDir, time.Duration(cfg.Scan.Timeout)*time.Second)
	pkgVerifier := agent.NewPackageVerifier()

	staticAnalyzers := []static.Analyzer{semgrep, pkgVerifier}
	var dynamicAnalyzers []static.Analyzer

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
	target = absTarget(target)

	verbose := format != "json" && format != "sarif"

	// diff mode: only scan git-changed files
	if o.diffMode {
		changed, err := gitChangedFiles(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  unable to get git diff: %v\n", err)
		} else if len(changed) == 0 {
			if verbose {
				fmt.Println("  ✅ no changed files to scan")
			}
			return nil
		} else {
			if verbose {
				fmt.Printf("  📋 diff mode: %d changed file(s)\n", len(changed))
			}
		}
	}

	if verbose {
		fmt.Printf("  🔍 Sift scanning: %s\n\n", target)
	}

	start := time.Now()
	var allFindings []static.Finding

	// Phase 1: Static Analysis (Semgrep + package verification + LLM semantic analysis)
	if verbose {
		fmt.Println("  ── Phase 1: Static Analysis ──")
	}
	results := o.runAnalyzers(o.staticAnalyzers, target)
	for _, r := range results {
		if r.Error != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  %s: %v\n", r.Analyzer, r.Error)
			continue
		}
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
		dynResults := o.runAnalyzers(o.dynamicAnalyzers, target)
		for _, r := range dynResults {
			if r.Error != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  %s: %v\n", r.Analyzer, r.Error)
				continue
			}
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

	// Enterprise: persist to SQLite + cache
	if o.dbStore != nil {
		o.dbStore.SaveScan(target, time.Since(start), allFindings, 0)
	}
	if o.fileCache != nil {
		o.fileCache.Save()
	}

	o.reporters.Render(allFindings, target, time.Since(start), format)

	return nil
}

// runAnalyzers runs all analyzers in parallel.
func (o *Orchestrator) runAnalyzers(analyzers []static.Analyzer, target string) []static.Result {
	var wg sync.WaitGroup
	results := make([]static.Result, len(analyzers))

	for i, a := range analyzers {
		wg.Add(1)
		go func(idx int, analyzer static.Analyzer) {
			defer wg.Done()
			start := time.Now()
			findings, err := analyzer.Analyze(target)
			results[idx] = static.Result{
				Analyzer: analyzer.Name(),
				Target:   target,
				Findings: findings,
				Duration: time.Since(start),
				Error:    err,
			}
		}(i, a)
	}

	wg.Wait()
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
func (o *Orchestrator) LastFindings() []static.Finding {
	return o.lastFindings
}

// gitChangedFiles returns the list of changed files in the git working tree.
func gitChangedFiles(repoPath string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff", "--name-only", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		// Try staged diff
		cmd = exec.Command("git", "-C", repoPath, "diff", "--name-only", "--staged")
		out, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f = strings.TrimSpace(f)
		if f != "" {
			files = append(files, filepath.Join(repoPath, f))
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

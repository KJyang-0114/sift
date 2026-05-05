package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KJyang-0114/sift/internal/agent"
	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/report"
	"github.com/KJyang-0114/sift/internal/static"
)

// Orchestrator 協調所有分析器，執行全自動掃描流程。
type Orchestrator struct {
	cfg        *config.Config
	analyzers  []static.Analyzer
	reporters  *report.Engine
}

// NewOrchestrator 建立掃描協調器。
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	rulesDir := findRulesDir()

	semgrep := static.NewSemgrepAnalyzer(rulesDir, time.Duration(cfg.Scan.Timeout)*time.Second)
	pkgVerifier := agent.NewPackageVerifier()

	return &Orchestrator{
		cfg: cfg,
		analyzers: []static.Analyzer{
			semgrep,
			pkgVerifier,
		},
		reporters: report.NewEngine(cfg),
	}
}

// Run 執行完整掃描流程。
func (o *Orchestrator) Run(target string, format string) error {
	// 解析目標路徑
	target = absTarget(target)

	fmt.Printf("  🔍 Sift 掃描中: %s\n\n", target)

	start := time.Now()
	var allFindings []static.Finding

	// Phase 1: 靜態分析（並行執行）
	fmt.Println("  ── Phase 1: 靜態分析 ──")
	results := o.runAnalyzers(target)
	for _, r := range results {
		if r.Error != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  %s: %v\n", r.Analyzer, r.Error)
			continue
		}
		fmt.Printf("  ✅ %s: %d 個問題\n", r.Analyzer, len(r.Findings))
		allFindings = append(allFindings, r.Findings...)
	}

	fmt.Println()

	// 輸出報告
	o.reporters.Render(allFindings, target, time.Since(start), format)

	return nil
}

// runAnalyzers 並行執行所有分析器。
func (o *Orchestrator) runAnalyzers(target string) []static.Result {
	var wg sync.WaitGroup
	results := make([]static.Result, len(o.analyzers))

	for i, a := range o.analyzers {
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

// findRulesDir 找到規則目錄。
func findRulesDir() string {
	// 從專案目錄找
	if cwd, err := os.Getwd(); err == nil {
		dir := filepath.Join(cwd, "internal", "static", "rules")
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return "internal/static/rules"
}

func absTarget(target string) string {
	if abs, err := filepath.Abs(target); err == nil {
		return abs
	}
	return target
}

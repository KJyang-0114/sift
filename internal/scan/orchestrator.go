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

// Orchestrator 協調所有分析器，執行全自動掃描流程。
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

// SetDiffMode 啟用 diff 模式，僅掃描 git 變更的檔案。
func (o *Orchestrator) SetDiffMode(enabled bool) {
	o.diffMode = enabled
}

// NewOrchestrator 建立掃描協調器。
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	rulesDir := findRulesDir()

	semgrep := static.NewSemgrepAnalyzer(rulesDir, time.Duration(cfg.Scan.Timeout)*time.Second)
	pkgVerifier := agent.NewPackageVerifier()

	staticAnalyzers := []static.Analyzer{semgrep, pkgVerifier}
	var dynamicAnalyzers []static.Analyzer

	// 如果設定了 LLM，加入語意分析和測試生成
	if cfg.LLM.Provider != config.ProviderOffline && cfg.LLM.APIKey != "" {
		if sa, err := agent.NewSemanticAnalyzer(cfg); err == nil {
			staticAnalyzers = append(staticAnalyzers, sa)
		}
		if tg, err := agent.NewTestGenerator(cfg); err == nil {
			dynamicAnalyzers = append(dynamicAnalyzers, tg)
		}
	}

	// 企業級：初始化快取（增量掃描）
	fc, _ := cache.NewFileCache(".")

	// 企業級：初始化 SQLite 持久化
	dbStore, _ := store.NewStore(".")

	// 企業級：Worker Pool（控制並發數、避免 API Rate Limit）
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

// Run 執行完整掃描流程。
func (o *Orchestrator) Run(target string, format string) error {
	target = absTarget(target)

	verbose := format != "json" && format != "sarif"

	// diff 模式：僅掃描 git 變更檔案
	if o.diffMode {
		changed, err := gitChangedFiles(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  無法取得 git diff: %v\n", err)
		} else if len(changed) == 0 {
			if verbose {
				fmt.Println("  ✅ 沒有變更的檔案需要掃描")
			}
			return nil
		} else {
			if verbose {
				fmt.Printf("  📋 diff 模式：%d 個變更檔案\n", len(changed))
			}
		}
	}

	if verbose {
		fmt.Printf("  🔍 Sift 掃描中: %s\n\n", target)
	}

	start := time.Now()
	var allFindings []static.Finding

	// Phase 1: 靜態分析（Semgrep + 套件驗證 + LLM 語意分析）
	if verbose {
		fmt.Println("  ── Phase 1: 靜態分析 ──")
	}
	results := o.runAnalyzers(o.staticAnalyzers, target)
	for _, r := range results {
		if r.Error != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  %s: %v\n", r.Analyzer, r.Error)
			continue
		}
		if verbose {
			fmt.Printf("  ✅ %s: %d 個問題\n", r.Analyzer, len(r.Findings))
		}
		allFindings = append(allFindings, r.Findings...)
	}

	// Phase 2: 動態測試（沙盒執行，僅在有 LLM 時啟用）
	if len(o.dynamicAnalyzers) > 0 {
		if verbose {
			fmt.Println()
			fmt.Println("  ── Phase 2: 動態測試 ──")
		}
		dynResults := o.runAnalyzers(o.dynamicAnalyzers, target)
		for _, r := range dynResults {
			if r.Error != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  %s: %v\n", r.Analyzer, r.Error)
				continue
			}
			if verbose {
				fmt.Printf("  ✅ %s: %d 個問題\n", r.Analyzer, len(r.Findings))
			}
			allFindings = append(allFindings, r.Findings...)
		}
	}

	if verbose {
		fmt.Println()
	}

	// 輸出報告
	o.lastFindings = allFindings

	// 企業級：持久化到 SQLite + 快取
	if o.dbStore != nil {
		o.dbStore.SaveScan(target, time.Since(start), allFindings, 0)
	}
	if o.fileCache != nil {
		o.fileCache.Save()
	}

	o.reporters.Render(allFindings, target, time.Since(start), format)

	return nil
}

// runAnalyzers 並行執行所有分析器。
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

// findRulesDir 找到規則目錄。
func findRulesDir() string {
	if cwd, err := os.Getwd(); err == nil {
		dir := filepath.Join(cwd, "internal", "static", "rules")
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return "internal/static/rules"
}

// LastFindings 回傳最近一次掃描的所有 findings。
func (o *Orchestrator) LastFindings() []static.Finding {
	return o.lastFindings
}

// gitChangedFiles 回傳 git 工作區中變更的檔案列表。
func gitChangedFiles(repoPath string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff", "--name-only", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		// 嘗試 diff staged
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

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/llm"
	"github.com/KJyang-0114/sift/internal/static"
)

// SemanticAnalyzer uses LLM to perform semantic-level security and logic analysis on code.
type SemanticAnalyzer struct {
	client llm.Client
	cfg    *config.Config
}

// NewSemanticAnalyzer creates a semantic analyzer.
func NewSemanticAnalyzer(cfg *config.Config) (*SemanticAnalyzer, error) {
	client, err := llm.NewClient(&cfg.LLM)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("LLM not configured, cannot perform semantic analysis. Run sift init")
	}
	return &SemanticAnalyzer{
		client: client,
		cfg:    cfg,
	}, nil
}

// Name returns the analyzer name.
func (sa *SemanticAnalyzer) Name() string {
	return "llm-semantic"
}

// Analyze performs LLM semantic analysis on the target code.
func (sa *SemanticAnalyzer) Analyze(target string) ([]static.Finding, error) {
	// Collect files to analyze (max 20 files to control costs)
	files, err := sa.collectFiles(target, 20)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, nil
	}

	var allFindings []static.Finding

	// Analyze each file individually
	for _, file := range files {
		findings, err := sa.analyzeFile(file)
		if err != nil {
			// Skip individual file analysis failures, do not abort the overall scan
			fmt.Fprintf(os.Stderr, "  ⚠️  LLM analysis of %s failed: %v\n", file, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// analyzeFile uses LLM to analyze a single file.
func (sa *SemanticAnalyzer) analyzeFile(path string) ([]static.Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Skip empty files
	if len(strings.TrimSpace(string(content))) == 0 {
		return nil, nil
	}

	// Limit token usage: max 8000 characters per file
	code := string(content)
	if len(code) > 8000 {
		code = code[:8000] + "\n// ... (truncated)"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := sa.client.Chat(ctx, semanticSystemPrompt, fmt.Sprintf(semanticUserTemplate, path, detectLang(path), code))
	if err != nil {
		return nil, err
	}

	return parseSemanticResult(result, path)
}

// collectFiles collects files suitable for LLM analysis from the target directory.
func (sa *SemanticAnalyzer) collectFiles(target string, maxFiles int) ([]string, error) {
	var files []string

	// Priority file extensions
	priorityExts := map[string]bool{
		".py": true, ".js": true, ".ts": true, ".tsx": true,
		".go": true, ".java": true, ".rb": true, ".php": true,
		".rs": true, ".c": true, ".cpp": true, ".h": true,
	}

	skipDirs := map[string]bool{
		"node_modules": true, "vendor": true, ".git": true,
		"__pycache__": true, "dist": true, "target": true,
		"build": true, ".next": true, ".svelte-kit": true,
		"venv": true, ".venv": true, "site-packages": true,
	}

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if len(files) >= maxFiles || info.Size() > 100*1024 {
			return nil
		}

		ext := filepath.Ext(path)
		if priorityExts[ext] {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

func detectLang(path string) string {
	ext := filepath.Ext(path)
	switch ext {
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".go":
		return "go"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".rs":
		return "rust"
	case ".c", ".h":
		return "c"
	case ".cpp", ".hpp":
		return "cpp"
	default:
		return ""
	}
}

// ── LLM Prompt Design ──

const semanticSystemPrompt = `You are a senior security engineer performing code review.
Analyze the given code for security vulnerabilities and logic errors.

Focus ONLY on:
1. Security bugs (SQL injection, XSS, command injection, path traversal, SSRF)
2. Prompt Injection risks (user input flowing unfiltered into LLM calls)
3. Logic errors (dead code, unreachable branches, off-by-one, nil/null pointer risks)
4. Race conditions in concurrent code

DO NOT flag:
- Style issues, naming conventions, formatting
- Missing comments or documentation
- Performance optimizations that don't affect correctness

Respond with a JSON array of findings. Each finding must have:
- "severity": "critical" | "high" | "medium" | "low"
- "line": approximate line number (integer)
- "message": one-line description in English
- "category": "security" | "logic" | "prompt-injection"

If no issues found, respond with an empty array: []

IMPORTANT: Respond ONLY with the JSON array, no other text.`

const semanticUserTemplate = `File: %s
Language: %s

---CODE---
%s
---END CODE---

Find security vulnerabilities and logic errors. Output JSON array only.`

// semanticFinding is the structure returned by the LLM.
type semanticFinding struct {
	Severity string `json:"severity"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
	Category string `json:"category"`
}

func parseSemanticResult(result string, file string) ([]static.Finding, error) {
	// LLM sometimes adds extra text before/after JSON, need to extract the JSON array
	jsonStr := extractJSONArray(result)
	if jsonStr == "" {
		return nil, nil
	}

	var sf []semanticFinding
	if err := json.Unmarshal([]byte(jsonStr), &sf); err != nil {
		// JSON parse failure should not abort the entire scan
		return nil, nil
	}

	var findings []static.Finding
	for _, f := range sf {
		sev := mapLLMSeverity(f.Severity)
		findings = append(findings, static.Finding{
			ID:       "sift.llm-" + f.Category,
			Rule:     "sift.llm-" + f.Category,
			Message:  fmt.Sprintf("[LLM] %s", f.Message),
			Severity: sev,
			Category: f.Category,
			File:     file,
			Line:     f.Line,
			Column:   0,
		})
	}

	return findings, nil
}

func extractJSONArray(s string) string {
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start == -1 || end == -1 || start >= end {
		return ""
	}
	return s[start : end+1]
}

func mapLLMSeverity(s string) static.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return static.SeverityCritical
	case "high":
		return static.SeverityHigh
	case "medium":
		return static.SeverityMedium
	case "low":
		return static.SeverityLow
	default:
		return static.SeverityMedium
	}
}

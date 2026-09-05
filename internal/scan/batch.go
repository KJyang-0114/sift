package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/llm"
)

// BatchAnalyzer sends multiple files to the LLM in batches, dramatically reducing API calls.
// Enterprise feature: For large projects with 1000+ files, batch mode reduces API calls by 10-20x.
type BatchAnalyzer struct {
	client    llm.Client
	batchSize int
	timeout   time.Duration
}

// NewBatchAnalyzer creates a batch analyzer.
func NewBatchAnalyzer(client llm.Client, batchSize int, timeout time.Duration) *BatchAnalyzer {
	if batchSize <= 0 {
		batchSize = 5 // Default: 5 files per batch
	}
	return &BatchAnalyzer{
		client:    client,
		batchSize: batchSize,
		timeout:   timeout,
	}
}

const batchSystemPrompt = `You are a senior security engineer. Analyze the following code files for security issues.
For each issue found, output a JSON object with: file, line, severity, category, message.
Categories: security, logic, prompt-injection, config-security.

Output format (one per line, JSON objects):
{"file": "...", "line": N, "severity": "high", "category": "security", "message": "..."}

If no issues found in a file, skip it. Focus on REAL vulnerabilities, not style issues.`

// AnalyzeBatch performs batch analysis on multiple files.
func (ba *BatchAnalyzer) AnalyzeBatch(ctx context.Context, request core.ScanRequest, files map[string]string) core.AnalysisResult {
	analysis := core.AnalysisResult{Findings: []core.Finding{}, Diagnostics: []core.Diagnostic{}}
	if len(files) == 0 {
		return analysis
	}

	// Build batch request
	var sb strings.Builder
	sb.WriteString("Analyze the following files for vulnerabilities:\n\n")
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		content := files[path]
		// Truncate oversized files
		code := content
		if len(code) > 3000 {
			code = code[:3000] + "\n// ... (truncated for analysis)"
		}
		sb.WriteString(fmt.Sprintf("### %s\n```\n%s\n```\n\n", path, code))
	}

	callCtx, cancel := context.WithTimeout(ctx, ba.timeout)
	defer cancel()

	result, err := ba.client.Chat(callCtx, batchSystemPrompt, sb.String())
	if err != nil {
		analysis.Diagnostics = append(analysis.Diagnostics, core.Diagnostic{
			Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
			Code: "llm-batch.request", Source: "llm-batch", Message: err.Error(), Cause: err,
		})
		return analysis
	}

	analysis.Findings, analysis.Diagnostics = parseBatchResults(result, request)
	return analysis
}

// batchIssue represents a single issue returned by the LLM batch.
type batchIssue struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Message  string `json:"message"`
}

func parseBatchResults(result string, request core.ScanRequest) ([]core.Finding, []core.Diagnostic) {
	findings := []core.Finding{}
	diagnostics := []core.Diagnostic{}

	// Parse JSON objects on each line
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}

		var issue batchIssue
		if err := json.Unmarshal([]byte(line), &issue); err != nil {
			diagnostics = append(diagnostics, core.Diagnostic{
				Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
				Code: "llm-batch.invalid-output", Source: "llm-batch", Message: err.Error(), Cause: err,
			})
			continue
		}
		relativePath, err := request.RelativePath(issue.File)
		if err != nil {
			diagnostics = append(diagnostics, core.Diagnostic{
				Kind: core.DiagnosticTarget, Severity: core.DiagnosticError,
				Code: "llm-batch.location.outside-root", Source: "llm-batch",
				Message: "Batch model returned a location outside the scan root", Cause: err,
			})
			continue
		}
		category := strings.TrimSpace(issue.Category)
		if category == "" {
			category = "security"
		}
		finding, err := core.NewFinding(core.FindingInput{
			Source: "llm-batch", Rule: "sift.llm-" + category,
			Message:  fmt.Sprintf("[LLM Batch] %s", strings.TrimSpace(issue.Message)),
			Severity: parseSeverity(issue.Severity), Category: category, Confidence: core.ConfidenceLow,
			Location: core.Location{Path: relativePath, Line: issue.Line},
			Evidence: []core.Evidence{{
				Kind:        core.EvidenceModel,
				Description: "An optional language model identified this candidate in a batch response; deterministic confirmation is required.",
			}},
			Remediation: "Confirm the reported issue with deterministic analysis before applying a targeted fix.",
			StableKey:   fmt.Sprintf("%d:%s", issue.Line, strings.TrimSpace(issue.Message)),
		})
		if err != nil {
			diagnostics = append(diagnostics, core.Diagnostic{
				Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
				Code: "llm-batch.invalid-finding", Source: "llm-batch", Message: err.Error(), Cause: err,
			})
			continue
		}
		findings = append(findings, finding)
	}

	return findings, diagnostics
}

func parseSeverity(s string) core.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return core.SeverityCritical
	case "high":
		return core.SeverityHigh
	case "medium":
		return core.SeverityMedium
	case "low":
		return core.SeverityLow
	default:
		return core.SeverityMedium
	}
}

package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/llm"
	"github.com/KJyang-0114/sift/internal/static"
)

// BatchAnalyzer sends multiple files to the LLM in batches, dramatically reducing API calls.
// Enterprise feature: For large projects with 1000+ files, batch mode reduces API calls by 10-20x.
type BatchAnalyzer struct {
	client   llm.Client
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
func (ba *BatchAnalyzer) AnalyzeBatch(files map[string]string) ([]static.Finding, error) {
	if len(files) == 0 {
		return nil, nil
	}

	// Build batch request
	var sb strings.Builder
	sb.WriteString("Analyze the following files for vulnerabilities:\n\n")
	for path, content := range files {
		// Truncate oversized files
		code := content
		if len(code) > 3000 {
			code = code[:3000] + "\n// ... (truncated for analysis)"
		}
		sb.WriteString(fmt.Sprintf("### %s\n```\n%s\n```\n\n", path, code))
	}

	ctx, cancel := context.WithTimeout(context.Background(), ba.timeout)
	defer cancel()

	result, err := ba.client.Chat(ctx, batchSystemPrompt, sb.String())
	if err != nil {
		return nil, err
	}

	return parseBatchResults(result), nil
}

// batchIssue represents a single issue returned by the LLM batch.
type batchIssue struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Message  string `json:"message"`
}

func parseBatchResults(result string) []static.Finding {
	var findings []static.Finding

	// Parse JSON objects on each line
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}

		// Simple JSON parsing
		var issue batchIssue
		if err := jsonUnmarshalSimple(line, &issue); err != nil {
			continue
		}

		findings = append(findings, static.Finding{
			Rule:     "sift.llm-" + issue.Category,
			Severity: parseSeverity(issue.Severity),
			Category: issue.Category,
			File:     issue.File,
			Line:     issue.Line,
			Message:  fmt.Sprintf("[LLM Batch] %s", issue.Message),
		})
	}

	return findings
}

func jsonUnmarshalSimple(s string, v *batchIssue) error {
	// Minimal JSON parser, avoids the performance overhead of encoding/json
	extract := func(key string) string {
		start := strings.Index(s, `"`+key+`"`)
		if start == -1 {
			return ""
		}
		colon := strings.Index(s[start:], ":")
		if colon == -1 {
			return ""
		}
		rest := s[start+colon+1:]
		rest = strings.TrimSpace(rest)

		if strings.HasPrefix(rest, `"`) {
			rest = rest[1:]
			end := strings.Index(rest, `"`)
			if end == -1 {
				return rest
			}
			return rest[:end]
		}

		// Number
		end := strings.IndexAny(rest, ",}")
		if end == -1 {
			return rest
		}
		return strings.TrimSpace(rest[:end])
	}

	v.File = extract("file")
	v.Severity = extract("severity")
	v.Category = extract("category")
	v.Message = extract("message")

	lineStr := extract("line")
	if lineStr != "" {
		fmt.Sscanf(lineStr, "%d", &v.Line)
	}

	if v.File == "" {
		return fmt.Errorf("missing file")
	}
	return nil
}

func parseSeverity(s string) static.Severity {
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

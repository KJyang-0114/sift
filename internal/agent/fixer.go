package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/llm"
	"github.com/KJyang-0114/sift/internal/static"
)

// Fixer uses LLM to automatically generate and apply fixes.
type Fixer struct {
	client   llm.Client
	maxFixes int
}

// FixResult is the result of a single fix operation.
type FixResult struct {
	Finding   static.Finding `json:"finding"`
	Fixed     bool           `json:"fixed"`
	Patch     string         `json:"patch,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// NewFixer creates an auto-fixer.
func NewFixer(cfg *config.Config) (*Fixer, error) {
	client, err := llm.NewClient(&cfg.LLM)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("LLM not configured, cannot auto-fix. Run sift init")
	}
	return &Fixer{
		client:   client,
		maxFixes: 20,
	}, nil
}

// Name returns the analyzer name.
func (f *Fixer) Name() string {
	return "auto-fixer"
}

// Fix generates fix suggestions for each finding in the list.
// Returns the fix result for each finding.
func (f *Fixer) Fix(findings []static.Finding) []FixResult {
	var results []FixResult

	count := 0
	for _, finding := range findings {
		if count >= f.maxFixes {
			break
		}

		result := FixResult{Finding: finding}
		patch, err := f.generateFix(finding)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		result.Patch = patch
		result.Fixed = true
		results = append(results, result)
		count++
	}

	return results
}

// ApplyFix applies a single fix to a file.
func (f *Fixer) ApplyFix(result FixResult) error {
	if !result.Fixed || result.Patch == "" {
		return fmt.Errorf("no fix available to apply")
	}

	// Read original file
	content, err := os.ReadFile(result.Finding.File)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Backup original content
	backup := string(content)
	backupPath := result.Finding.File + ".sift.bak"
	_ = os.WriteFile(backupPath, content, 0o644)

	// Apply patch
	patched, err := applyPatch(string(content), result.Patch)
	if err != nil {
		return fmt.Errorf("failed to apply fix: %w", err)
	}

	// Write back to file
	if err := os.WriteFile(result.Finding.File, []byte(patched), 0o644); err != nil {
		// Rollback
		os.WriteFile(result.Finding.File, []byte(backup), 0o644)
		return fmt.Errorf("failed to write fix: %w", err)
	}

	return nil
}

// RollbackFix reverts an applied fix.
func (f *Fixer) RollbackFix(filePath string) error {
	backupPath := filePath + ".sift.bak"
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	if err := os.WriteFile(filePath, backup, 0o644); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	os.Remove(backupPath)
	return nil
}

const fixerSystemPrompt = `You are an expert security engineer fixing code vulnerabilities.

Given a security finding (file, line, issue description, code snippet), generate the EXACT code fix.

Output format:
- First line: the file path and line number in format "// file: path/to/file.ts:LINE"
- Then the diff in unified format:
  - old code (prefixed with "- ")
  + new code (prefixed with "+ ")

Rules:
1. Make MINIMAL changes - only fix the specific issue, don't refactor unrelated code
2. Preserve exact indentation (tabs/spaces)
3. For SQL injection: convert to parameterized queries
4. For XSS: add HTML escaping or DOMPurify
5. For hardcoded secrets: replace with process.env.VAR_NAME
6. For path traversal: add path.resolve + prefix check
7. For prompt injection: add input sanitization
8. If the code already looks safe, output "NO_FIX_NEEDED"

IMPORTANT: Output ONLY the fix. No explanations.`

const fixerUserTemplate = `Fix this security issue:

- File: %s
- Line: %d
- Severity: %s
- Rule: %s
- Issue: %s
- Code:
  %s

Generate the exact code fix (old → new).`

// generateFix uses LLM to generate a fix for a single issue.
func (f *Fixer) generateFix(finding static.Finding) (string, error) {
	// Read file content (5 lines of context before and after)
	fileContent, err := os.ReadFile(finding.File)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(fileContent), "\n")
	start := max(finding.Line-6, 0)
	end := min(finding.Line+5, len(lines))
	contextLines := strings.Join(lines[start:end], "\n")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	userMsg := fmt.Sprintf(fixerUserTemplate,
		finding.File, finding.Line, finding.Severity, finding.Rule, finding.Message, contextLines,
	)

	result, err := f.client.Chat(ctx, fixerSystemPrompt, userMsg)
	if err != nil {
		return "", err
	}

	if strings.Contains(result, "NO_FIX_NEEDED") {
		return "", fmt.Errorf("LLM determined this issue does not need a fix")
	}

	return strings.TrimSpace(result), nil
}

// applyPatch applies the fix based on the diff text produced by the LLM.
func applyPatch(original, patch string) (string, error) {
	// Try to parse diff format: - old\n+ new
	lines := strings.Split(patch, "\n")
	var oldCode, newCode string
	inOld := false
	inNew := false

	for _, line := range lines {
		if strings.HasPrefix(line, "- ") {
			oldCode += strings.TrimPrefix(line, "- ") + "\n"
			inOld = true
		} else if strings.HasPrefix(line, "+ ") {
			newCode += strings.TrimPrefix(line, "+ ") + "\n"
			inNew = true
		}
	}

	if !inOld || !inNew {
		// Not standard diff format, try direct replacement
		return original, fmt.Errorf("unable to parse fix format")
	}

	oldCode = strings.TrimRight(oldCode, "\n")
	newCode = strings.TrimRight(newCode, "\n")

	if oldCode == "" {
		return original, fmt.Errorf("empty old code")
	}

	// Perform replacement
	result := strings.Replace(original, oldCode, newCode, 1)
	if result == original {
		// Try removing whitespace differences
		oldTrimmed := strings.TrimSpace(oldCode)
		idx := strings.Index(original, oldTrimmed)
		if idx >= 0 {
			result = original[:idx] + strings.TrimSpace(newCode) + original[idx+len(oldTrimmed):]
			return result, nil
		}
		return original, fmt.Errorf("could not find the code to replace in the original file")
	}

	return result, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CleanupBackups removes all .sift.bak backup files in the project.
func CleanupBackups(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.HasSuffix(path, ".sift.bak") {
			os.Remove(path)
		}
		return nil
	})
}

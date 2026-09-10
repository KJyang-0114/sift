package static

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/securepath"
)

// SemgrepAnalyzer uses the semgrep CLI to perform static analysis.
type SemgrepAnalyzer struct {
	configDir string
	timeout   time.Duration
}

var _ core.Analyzer = (*SemgrepAnalyzer)(nil)

// NewSemgrepAnalyzer creates a new Semgrep analyzer.
// configDir is the directory containing custom rules.
func NewSemgrepAnalyzer(configDir string, timeout time.Duration) *SemgrepAnalyzer {
	return &SemgrepAnalyzer{
		configDir: configDir,
		timeout:   timeout,
	}
}

// Name returns the analyzer name.
func (s *SemgrepAnalyzer) Name() string {
	return "semgrep"
}

// findSemgrep searches for the semgrep binary.
// Searches PATH and common Python bin directories.
func findSemgrep() (string, error) {
	if path, err := exec.LookPath("semgrep"); err == nil {
		return path, nil
	}

	// Search common Python installation locations
	searchPaths := []string{
		os.ExpandEnv("$HOME/Library/Python/3.*/bin"),
		os.ExpandEnv("$HOME/.local/bin"),
		"/Library/Frameworks/Python.framework/Versions/3.*/bin",
		"/usr/local/bin",
	}

	for _, pattern := range searchPaths {
		matches, err := filepath.Glob(filepath.Join(pattern, "semgrep"))
		if err != nil || len(matches) == 0 {
			continue
		}
		return matches[0], nil
	}

	return "", fmt.Errorf("semgrep not found")
}

// EnsureInstalled locates Semgrep without modifying the host environment.
func EnsureInstalled() (string, error) {
	path, err := findSemgrep()
	if err != nil {
		return "", fmt.Errorf("%w; install Semgrep before scanning (pip install semgrep)", err)
	}
	return path, nil
}

// Analyze runs Semgrep for the resolved request targets.
func (s *SemgrepAnalyzer) Analyze(ctx context.Context, request core.ScanRequest) core.AnalysisResult {
	result := core.AnalysisResult{Findings: []core.Finding{}, Diagnostics: []core.Diagnostic{}}
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		result.Diagnostics = append(result.Diagnostics, analyzerDiagnostic("semgrep.cancelled", err))
		return result
	}
	semgrepPath, err := EnsureInstalled()
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, analyzerDiagnostic("semgrep.unavailable", err))
		return result
	}

	// Write rules to temp directory
	ruleDir, err := s.writeRules()
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, analyzerDiagnostic("semgrep.rules", fmt.Errorf("write rules: %w", err)))
		return result
	}
	defer os.RemoveAll(ruleDir)

	// Execute semgrep (exclude third-party dependency directories to reduce noise)
	args := []string{
		"scan",
		"--config", ruleDir,
		"--json",
		"--no-git-ignore",
		"--exclude", "venv",
		"--exclude", ".venv",
		"--exclude", "node_modules",
		"--exclude", "site-packages",
		"--exclude", "__pycache__",
		"--exclude", "dist",
		"--exclude", "target",
		"--exclude", ".git",
	}

	args = append(args, request.AbsoluteTargets()...)

	cmd := exec.CommandContext(ctx, semgrepPath, args...)
	cmd.Dir = request.Root()
	// Both streams are bounded. Stderr becomes a diagnostic instead of bypassing
	// the selected report format; output overflow must not become a clean scan.
	stdout := &boundedOutput{limit: 32 * 1024 * 1024}
	stderr := &boundedOutput{limit: core.MaxEvidenceSnippetBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	runErr := cmd.Run()
	if stdout.truncated {
		result.Diagnostics = append(result.Diagnostics, analyzerDiagnostic("semgrep.output-limit", fmt.Errorf("Semgrep output exceeded %d bytes", stdout.limit)))
	} else if stdout.buffer.Len() > 0 {
		result.Findings, result.Diagnostics = parseSemgrepOutput([]byte(stdout.buffer.String()), request)
	} else if runErr == nil {
		result.Diagnostics = append(result.Diagnostics, analyzerDiagnostic("semgrep.invalid-output", fmt.Errorf("Semgrep returned no JSON report")))
	}
	if ctx.Err() != nil {
		result.Diagnostics = append(result.Diagnostics, analyzerDiagnostic("semgrep.cancelled", ctx.Err()))
	} else if runErr != nil {
		var exitErr *exec.ExitError
		// Semgrep's documented exit 1 denotes findings only when valid findings
		// accompany it. All other failures retain any successfully parsed results.
		findingsExit := errors.As(runErr, &exitErr) && exitErr.ExitCode() == 1 && len(result.Findings) > 0
		if !findingsExit {
			detail := strings.TrimSpace(stderr.buffer.String())
			detail = strings.ReplaceAll(detail, request.Root(), "<scan-root>")
			detail = strings.ReplaceAll(detail, ruleDir, "<rules>")
			if stderr.truncated {
				detail += " [truncated]"
			}
			message := fmt.Errorf("Semgrep execution failed: %w", runErr)
			if detail != "" {
				message = fmt.Errorf("%w: %s", message, detail)
			}
			result.Diagnostics = append(result.Diagnostics, analyzerDiagnostic("semgrep.execution", message))
		}
	}
	return result
}

// boundedOutput consumes all writes while retaining only a fixed-size prefix.
type boundedOutput struct {
	buffer    strings.Builder
	limit     int
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	count := len(p)
	remaining := b.limit - b.buffer.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(p)
	return count, nil
}

func analyzerDiagnostic(code string, err error) core.Diagnostic {
	return core.Diagnostic{
		Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
		Code: code, Source: "semgrep", Message: err.Error(), Cause: err,
	}
}

// writeRules writes rules to a temp directory for semgrep to use.
// Always copies to a temp directory to avoid defer RemoveAll accidentally deleting original rules.
func (s *SemgrepAnalyzer) writeRules() (string, error) {
	tmpDir, err := os.MkdirTemp("", "sift-rules-*")
	if err != nil {
		return "", err
	}

	// Prefer embedded rules (prod)
	if len(embeddedRules) > 0 {
		for name, content := range embeddedRules {
			rulePath := filepath.Join(tmpDir, name)
			if err := os.WriteFile(rulePath, []byte(content), 0o644); err != nil {
				os.RemoveAll(tmpDir)
				return "", err
			}
		}
		return tmpDir, nil
	}

	// Dev mode: copy from disk to temp directory
	if _, err := os.Stat(s.configDir); err == nil {
		entries, err := os.ReadDir(s.configDir)
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", err
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
				continue
			}
			src := filepath.Join(s.configDir, e.Name())
			dst := filepath.Join(tmpDir, e.Name())
			content, err := os.ReadFile(src)
			if err != nil {
				continue
			}
			if err := os.WriteFile(dst, content, 0o644); err != nil {
				os.RemoveAll(tmpDir)
				return "", err
			}
		}
		return tmpDir, nil
	}

	return tmpDir, nil
}

// embeddedRules stores embedded Semgrep rules (provided by rules.go embed).
var embeddedRules map[string]string

// semgrepResult is the structure of semgrep JSON output.
type semgrepResult struct {
	Results []semgrepFinding `json:"results"`
	Errors  []semgrepError   `json:"errors"`
}

type semgrepFinding struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Lines    string `json:"lines"`
		Metadata struct {
			Category string `json:"category"`
			CWE      string `json:"cwe"`
			OWASP    string `json:"owasp"`
		} `json:"metadata"`
	} `json:"extra"`
}

type semgrepError struct {
	Code    int    `json:"code"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Path    string `json:"path"`
}

func parseSemgrepOutput(output []byte, request core.ScanRequest) ([]core.Finding, []core.Diagnostic) {
	var result semgrepResult
	if err := json.Unmarshal(output, &result); err != nil {
		return []core.Finding{}, []core.Diagnostic{analyzerDiagnostic("semgrep.invalid-output", err)}
	}

	if result.Results == nil {
		return []core.Finding{}, []core.Diagnostic{analyzerDiagnostic("semgrep.invalid-output", fmt.Errorf("Semgrep JSON report is missing a results array"))}
	}
	findings := []core.Finding{}
	diagnostics := []core.Diagnostic{}
	for _, problem := range result.Errors {
		// Semgrep can report skipped/partially parsed files as warnings with exit 0.
		// Any entry in errors means Sift cannot claim complete analysis.
		message := strings.TrimSpace(problem.Message)
		if message == "" {
			message = fmt.Sprintf("Semgrep reported %s error %d", problem.Level, problem.Code)
		}
		message = strings.ReplaceAll(message, request.Root(), "<scan-root>")
		if len(message) > core.MaxEvidenceSnippetBytes {
			message = message[:core.MaxEvidenceSnippetBytes]
		}
		diagnostic := analyzerDiagnostic(fmt.Sprintf("semgrep.error.%d", problem.Code), errors.New(message))
		if problem.Path != "" {
			if path, err := request.RelativePath(problem.Path); err == nil {
				diagnostic.Path = path
			}
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	for _, r := range result.Results {
		severity := mapSemgrepSeverity(r.Extra.Severity)
		relativePath, err := request.RelativePath(r.Path)
		if err != nil {
			diagnostics = append(diagnostics, core.Diagnostic{
				Kind: core.DiagnosticTarget, Severity: core.DiagnosticError,
				Code: "semgrep.location.outside-root", Source: "semgrep",
				Message: "Semgrep returned a location outside the scan root", Cause: err,
			})
			continue
		}

		code := strings.TrimSpace(r.Extra.Lines)
		if idx := strings.Index(code, "\n"); idx != -1 {
			code = code[:idx]
		}
		// When Semgrep OSS does not return code, read it from source
		if code == "" || code == "requires login" {
			code = readLineFromFile(request.Root(), relativePath, r.Start.Line)
		}
		category := strings.TrimSpace(r.Extra.Metadata.Category)
		if category == "" {
			category = "security"
		}
		evidence := core.Evidence{Kind: core.EvidenceCode, Snippet: code}
		if evidence.Snippet == "" {
			evidence.Description = "Semgrep matched this rule at the reported source range."
		}
		finding, err := core.NewFinding(core.FindingInput{
			Source: "semgrep", Rule: r.CheckID, Message: strings.TrimSpace(r.Extra.Message),
			Severity: severity, Category: category, Confidence: core.ConfidenceHigh,
			Location: core.Location{
				Path: relativePath, Line: r.Start.Line, Column: r.Start.Col,
				EndLine: r.End.Line, EndColumn: r.End.Col,
			},
			Evidence:    []core.Evidence{evidence},
			Remediation: "Review the matched data flow and apply the remediation for this Semgrep rule.",
			CWE:         r.Extra.Metadata.CWE, OWASP: r.Extra.Metadata.OWASP,
			StableKey: fmt.Sprintf("%d:%d:%d:%d", r.Start.Line, r.Start.Col, r.End.Line, r.End.Col),
		})
		if err != nil {
			diagnostics = append(diagnostics, analyzerDiagnostic("semgrep.invalid-finding", err))
			continue
		}
		findings = append(findings, finding)
	}

	return findings, diagnostics
}

func readLineFromFile(baseDir, path string, lineNum int) string {
	data, err := securepath.ReadFile(baseDir, path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if lineNum > 0 && lineNum <= len(lines) {
		return strings.TrimSpace(lines[lineNum-1])
	}
	return ""
}

// splitCommaTargets splits a comma-separated target string into individual paths.
// When the target is a single directory or file (no commas), it returns a single-element slice.
// When the target contains commas (diff mode), each element is trimmed and empty strings are filtered.
func splitCommaTargets(target string) []string {
	if !strings.Contains(target, ",") {
		return []string{target}
	}
	var result []string
	for _, t := range strings.Split(target, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			result = append(result, t)
		}
	}
	if len(result) == 0 {
		return []string{target}
	}
	return result
}

func mapSemgrepSeverity(s string) core.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return core.SeverityCritical
	case "WARNING":
		return core.SeverityHigh
	case "INFO":
		return core.SeverityMedium
	default:
		return core.SeverityLow
	}
}

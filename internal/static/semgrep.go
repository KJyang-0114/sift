package static

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SemgrepAnalyzer uses the semgrep CLI to perform static analysis.
type SemgrepAnalyzer struct {
	configDir string
	timeout   time.Duration
}

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

// EnsureInstalled checks if semgrep is available, and auto-installs if not.
func EnsureInstalled() (string, error) {
	if path, err := findSemgrep(); err == nil {
		return path, nil
	}

	fmt.Fprintln(os.Stderr, "  ⚡ semgrep not installed, auto-installing...")

	// Try pip install
	pipCmds := []string{"pip3", "pip"}
	var installErr error
	for _, pip := range pipCmds {
		if _, err := exec.LookPath(pip); err == nil {
			cmd := exec.Command(pip, "install", "semgrep")
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			installErr = cmd.Run()
			if installErr == nil {
				if path, err := findSemgrep(); err == nil {
					return path, nil
				}
			}
		}
	}

	// Try brew (macOS)
	if _, err := exec.LookPath("brew"); err == nil {
		cmd := exec.Command("brew", "install", "semgrep")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err == nil {
			if path, err := findSemgrep(); err == nil {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("unable to auto-install semgrep: %w. "+
		"Please install manually: pip3 install semgrep or brew install semgrep", installErr)
}

// Analyze runs semgrep scan on the target path and parses the results.
func (s *SemgrepAnalyzer) Analyze(target string) ([]Finding, error) {
	semgrepPath, err := EnsureInstalled()
	if err != nil {
		return nil, err
	}

	// Write rules to temp directory
	ruleDir, err := s.writeRules()
	if err != nil {
		return nil, fmt.Errorf("failed to write rules: %w", err)
	}
	defer os.RemoveAll(ruleDir)

	start := time.Now()

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
		target,
	}

	cmd := exec.Command(semgrepPath, args...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		// semgrep returns non-zero when issues are found, but still outputs JSON
		if output == nil {
			return nil, fmt.Errorf("semgrep execution failed: %w", err)
		}
	}

	// Parse semgrep JSON output
	findings, err := parseSemgrepOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	_ = time.Since(start)

	return findings, nil
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

func parseSemgrepOutput(output []byte) ([]Finding, error) {
	var result semgrepResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, r := range result.Results {
		severity := mapSemgrepSeverity(r.Extra.Severity)

		code := strings.TrimSpace(r.Extra.Lines)
		if idx := strings.Index(code, "\n"); idx != -1 {
			code = code[:idx]
		}
		// When Semgrep OSS does not return code, read it from source
		if code == "" || code == "requires login" {
			code = readLineFromFile(r.Path, r.Start.Line)
		}

		findings = append(findings, Finding{
			ID:       r.CheckID,
			Rule:     r.CheckID,
			Message:  strings.TrimSpace(r.Extra.Message),
			Severity: severity,
			Category: r.Extra.Metadata.Category,
			File:     r.Path,
			Line:     r.Start.Line,
			Column:   r.Start.Col,
			Code:     code,
			CWE:      r.Extra.Metadata.CWE,
			OWASP:    r.Extra.Metadata.OWASP,
		})
	}

	return findings, nil
}

func readLineFromFile(path string, lineNum int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if lineNum > 0 && lineNum <= len(lines) {
		return strings.TrimSpace(lines[lineNum-1])
	}
	return ""
}

func mapSemgrepSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return SeverityCritical
	case "WARNING":
		return SeverityHigh
	case "INFO":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

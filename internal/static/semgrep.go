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

// SemgrepAnalyzer 使用 semgrep CLI 執行靜態分析。
type SemgrepAnalyzer struct {
	configDir string
	timeout   time.Duration
}

// NewSemgrepAnalyzer 建立新的 Semgrep 分析器。
// configDir 是包含自定義規則的目錄。
func NewSemgrepAnalyzer(configDir string, timeout time.Duration) *SemgrepAnalyzer {
	return &SemgrepAnalyzer{
		configDir: configDir,
		timeout:   timeout,
	}
}

// Name 回傳分析器名稱。
func (s *SemgrepAnalyzer) Name() string {
	return "semgrep"
}

// EnsureInstalled 確認 semgrep 是否可用，若否自動安裝。
func EnsureInstalled() error {
	if _, err := exec.LookPath("semgrep"); err == nil {
		return nil
	}

	fmt.Fprintln(os.Stderr, "  ⚡ semgrep 未安裝，自動安裝中...")

	// 嘗試 pip 安裝
	pipCmds := []string{"pip3", "pip"}
	var installErr error
	for _, pip := range pipCmds {
		if _, err := exec.LookPath(pip); err == nil {
			cmd := exec.Command(pip, "install", "semgrep")
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			installErr = cmd.Run()
			if installErr == nil {
				return nil
			}
		}
	}

	// 嘗試 brew（macOS）
	if _, err := exec.LookPath("brew"); err == nil {
		cmd := exec.Command("brew", "install", "semgrep")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	return fmt.Errorf("無法自動安裝 semgrep: %w。"+
		"請手動安裝: pip3 install semgrep 或 brew install semgrep", installErr)
}

// Analyze 對目標路徑執行 semgrep 掃描並解析結果。
func (s *SemgrepAnalyzer) Analyze(target string) ([]Finding, error) {
	if err := EnsureInstalled(); err != nil {
		return nil, err
	}

	// 寫入暫存規則目錄
	ruleDir, err := s.writeRules()
	if err != nil {
		return nil, fmt.Errorf("寫入規則失敗: %w", err)
	}
	defer os.RemoveAll(ruleDir)

	start := time.Now()

	// 執行 semgrep
	args := []string{
		"scan",
		"--config", ruleDir,
		"--json",
		"--no-git-ignore",
		"--verbose",
		target,
	}

	cmd := exec.Command("semgrep", args...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		// semgrep 找到問題時會返回非零，但仍然輸出 JSON
		if output == nil {
			return nil, fmt.Errorf("semgrep 執行失敗: %w", err)
		}
	}

	// 解析 semgrep JSON 輸出
	findings, err := parseSemgrepOutput(output)
	if err != nil {
		return nil, fmt.Errorf("解析 semgrep 輸出失敗: %w", err)
	}

	_ = time.Since(start)

	return findings, nil
}

// writeRules 將內嵌規則寫入暫存目錄供 semgrep 使用。
func (s *SemgrepAnalyzer) writeRules() (string, error) {
	// 如果 configDir 存在（開發模式），直接用
	if _, err := os.Stat(s.configDir); err == nil {
		return s.configDir, nil
	}

	// 使用內嵌規則
	tmpDir, err := os.MkdirTemp("", "sift-rules-*")
	if err != nil {
		return "", err
	}

	// 走訪所有內嵌規則，寫入暫存目錄
	for name, content := range embeddedRules {
		rulePath := filepath.Join(tmpDir, name)
		if err := os.WriteFile(rulePath, []byte(content), 0o644); err != nil {
			os.RemoveAll(tmpDir)
			return "", err
		}
	}

	return tmpDir, nil
}

// embeddedRules 內嵌的 Semgrep 規則（由 rules.go 的 embed 提供）。
var embeddedRules map[string]string

// semgrepResult 是 semgrep JSON 輸出的結構。
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

		// 提取第一行程式碼
		code := strings.TrimSpace(r.Extra.Lines)
		if idx := strings.Index(code, "\n"); idx != -1 {
			code = code[:idx]
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

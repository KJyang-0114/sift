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

// Fixer 使用 LLM 自動產生並套用修復。
type Fixer struct {
	client   llm.Client
	maxFixes int
}

// FixResult 是一次修復操作的結果。
type FixResult struct {
	Finding   static.Finding `json:"finding"`
	Fixed     bool           `json:"fixed"`
	Patch     string         `json:"patch,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// NewFixer 建立自動修復器。
func NewFixer(cfg *config.Config) (*Fixer, error) {
	client, err := llm.NewClient(&cfg.LLM)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("LLM 未設定，無法自動修復。請執行 sift init")
	}
	return &Fixer{
		client:   client,
		maxFixes: 20,
	}, nil
}

// Name 回傳分析器名稱。
func (f *Fixer) Name() string {
	return "auto-fixer"
}

// Fix 對 findings 清單逐一產生修復建議。
// 回傳每個 finding 的修復結果。
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

// ApplyFix 套用單一修復到檔案。
func (f *Fixer) ApplyFix(result FixResult) error {
	if !result.Fixed || result.Patch == "" {
		return fmt.Errorf("沒有可套用的修復")
	}

	// 讀取原始檔案
	content, err := os.ReadFile(result.Finding.File)
	if err != nil {
		return fmt.Errorf("讀取檔案失敗: %w", err)
	}

	// 備份原始內容
	backup := string(content)
	backupPath := result.Finding.File + ".sift.bak"
	_ = os.WriteFile(backupPath, content, 0o644)

	// 套用 patch
	patched, err := applyPatch(string(content), result.Patch)
	if err != nil {
		return fmt.Errorf("套用修復失敗: %w", err)
	}

	// 寫回檔案
	if err := os.WriteFile(result.Finding.File, []byte(patched), 0o644); err != nil {
		// 還原
		os.WriteFile(result.Finding.File, []byte(backup), 0o644)
		return fmt.Errorf("寫入修復失敗: %w", err)
	}

	return nil
}

// RollbackFix 還原已套用的修復。
func (f *Fixer) RollbackFix(filePath string) error {
	backupPath := filePath + ".sift.bak"
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("找不到備份檔案: %s", backupPath)
	}

	if err := os.WriteFile(filePath, backup, 0o644); err != nil {
		return fmt.Errorf("還原失敗: %w", err)
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

// generateFix 使用 LLM 產生單一問題的修復。
func (f *Fixer) generateFix(finding static.Finding) (string, error) {
	// 讀取檔案內容（前後 5 行上下文）
	fileContent, err := os.ReadFile(finding.File)
	if err != nil {
		return "", fmt.Errorf("讀取檔案失敗: %w", err)
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
		return "", fmt.Errorf("LLM 判斷此問題不需要修復")
	}

	return strings.TrimSpace(result), nil
}

// applyPatch 根據 LLM 產生的 diff 文字套用修復。
func applyPatch(original, patch string) (string, error) {
	// 嘗試解析 diff 格式: - old\n+ new
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
		// 不是標準 diff 格式，嘗試直接替換
		return original, fmt.Errorf("無法解析修復格式")
	}

	oldCode = strings.TrimRight(oldCode, "\n")
	newCode = strings.TrimRight(newCode, "\n")

	if oldCode == "" {
		return original, fmt.Errorf("空的舊程式碼")
	}

	// 執行替換
	result := strings.Replace(original, oldCode, newCode, 1)
	if result == original {
		// 嘗試去除空白差異
		oldTrimmed := strings.TrimSpace(oldCode)
		idx := strings.Index(original, oldTrimmed)
		if idx >= 0 {
			result = original[:idx] + strings.TrimSpace(newCode) + original[idx+len(oldTrimmed):]
			return result, nil
		}
		return original, fmt.Errorf("在原始檔案中找不到要替換的程式碼")
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

// CleanupBackups 清除專案中所有 .sift.bak 備份檔案。
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

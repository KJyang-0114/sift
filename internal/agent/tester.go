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
	"github.com/KJyang-0114/sift/internal/sandbox"
	"github.com/KJyang-0114/sift/internal/static"
)

// TestGenerator 自動生成測試用例並在沙盒中執行。
type TestGenerator struct {
	client  llm.Client
	sandbox *sandbox.Orbital
	cfg     *config.Config
}

// NewTestGenerator 建立測試生成器。
func NewTestGenerator(cfg *config.Config) (*TestGenerator, error) {
	client, err := llm.NewClient(&cfg.LLM)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("LLM 未設定")
	}

	return &TestGenerator{
		client:  client,
		sandbox: sandbox.NewOrbital(time.Duration(cfg.Scan.Timeout) * time.Second),
		cfg:     cfg,
	}, nil
}

// Name 回傳分析器名稱。
func (tg *TestGenerator) Name() string {
	return "test-generator"
}

// Analyze 對目標程式碼生成並執行測試。
func (tg *TestGenerator) Analyze(target string) ([]static.Finding, error) {
	// 只處理 Python 檔案（MVP 階段優先支援）
	files, err := tg.collectPythonFiles(target, 10)
	if err != nil {
		return nil, err
	}

	var allFindings []static.Finding
	for _, file := range files {
		findings, err := tg.testFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  測試生成 %s 失敗: %v\n", file, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// testFile 對單一檔案生成測試並執行。
func (tg *TestGenerator) testFile(path string) ([]static.Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	code := string(content)
	if len(code) > 6000 {
		code = code[:6000]
	}

	// Step 1: 用 LLM 生成測試用例
	testCode, err := tg.generateTests(path, code)
	if err != nil || testCode == "" {
		return nil, err
	}

	// Step 2: 在沙盒中執行
	result, err := tg.sandbox.Run(testCode, "python")
	if err != nil {
		return nil, err
	}

	// Step 3: 分析結果
	var findings []static.Finding
	if result.TimedOut {
		findings = append(findings, static.Finding{
			ID:       "sift.test-timeout",
			Rule:     "sift.test-timeout",
			Message:  fmt.Sprintf("[動態測試] 測試執行超時，可能存在無限迴圈或效能問題。%s", result.Error),
			Severity: static.SeverityHigh,
			Category: "logic",
			File:     path,
		})
	}

	if result.ExitCode != 0 {
		findings = append(findings, static.Finding{
			ID:       "sift.test-failure",
			Rule:     "sift.test-failure",
			Message:  fmt.Sprintf("[動態測試] 自動生成的測試用例執行失敗 (exit: %d)。%s\n  Stderr: %s", result.ExitCode, result.Error, truncate(result.Stderr, 200)),
			Severity: static.SeverityHigh,
			Category: "logic",
			File:     path,
		})
	}

	return findings, nil
}

// collectPythonFiles 收集 Python 檔案。
func (tg *TestGenerator) collectPythonFiles(target string, maxFiles int) ([]string, error) {
	var files []string

	skipDirs := map[string]bool{
		"node_modules": true, "vendor": true, ".git": true,
		"__pycache__": true, "dist": true, "target": true,
		"build": true, ".venv": true, "venv": true,
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
		if len(files) >= maxFiles {
			return filepath.SkipAll
		}
		if filepath.Ext(path) == ".py" && !strings.HasPrefix(info.Name(), "test_") {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

const testGenSystemPrompt = `You are an expert QA engineer. Generate Python test code for the given function or module.

Rules:
1. Write pytest-style test functions
2. Include edge cases: empty input, None, very large values, boundary conditions
3. Each test function MUST start with "test_"
4. Import the code under test (assume it's in the same directory)
5. Use assertions (assert, not print)
6. Do NOT use external libraries beyond pytest
7. Keep tests focused and concise

Output ONLY the test code, no explanations. Include a final line that runs tests:
"if __name__ == '__main__':\n    import pytest\n    pytest.main([__file__, '-v', '--tb=short'])"
`

const testGenTemplate = `File: %s

---SOURCE CODE---
%s
---END---

Generate pytest test cases for the functions above. Output ONLY the Python test code.`

// generateTests 使用 LLM 為程式碼生成測試用例。
func (tg *TestGenerator) generateTests(path string, code string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := tg.client.Chat(ctx, testGenSystemPrompt, fmt.Sprintf(testGenTemplate, path, code))
	if err != nil {
		return "", err
	}

	// 提取程式碼區塊
	return extractCodeBlock(result), nil
}

// extractCodeBlock 從 LLM 回應中提取 ```python ... ``` 區塊。
func extractCodeBlock(response string) string {
	markers := []string{"```python", "```py", "```"}
	for _, marker := range markers {
		start := strings.Index(response, marker)
		if start == -1 {
			continue
		}
		start += len(marker)
		// 跳到下一行
		if nl := strings.Index(response[start:], "\n"); nl != -1 {
			start += nl + 1
		}
		end := strings.Index(response[start:], "```")
		if end == -1 {
			return strings.TrimSpace(response[start:])
		}
		return strings.TrimSpace(response[start : start+end])
	}
	return strings.TrimSpace(response)
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

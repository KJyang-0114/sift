package report

import (
	"fmt"
	"strings"

	"github.com/KJyang-0114/sift/internal/static"
)

// RenderLLM 以 LLM 可直接消費的格式輸出報告。
// 此格式專為貼給 LLM（如 Claude、GPT）設計，讓 LLM 可以直接產生修復程式碼。
func RenderLLM(findings []static.Finding, target string) {
	fmt.Println("# Code Issues Report")
	fmt.Println()
	fmt.Printf("The following security and logic issues were found in `%s`.\n", target)
	fmt.Println("For each issue, provide a specific code fix.")
	fmt.Println()

	if len(findings) == 0 {
		fmt.Println("✅ No issues found.")
		return
	}

	groups := static.GroupBySeverity(findings)
	order := []static.Severity{static.SeverityCritical, static.SeverityHigh, static.SeverityMedium, static.SeverityLow, static.SeverityInfo}

	idx := 0
	for _, sev := range order {
		for _, f := range groups[sev] {
			idx++
			fmt.Printf("## Issue %d [%s] %s\n", idx, strings.ToUpper(string(f.Severity)), f.Rule)
			fmt.Println()
			fmt.Printf("- **File**: `%s`\n", f.File)
			fmt.Printf("- **Line**: %d\n", f.Line)
			if f.CWE != "" {
				fmt.Printf("- **CWE**: %s\n", f.CWE)
			}
			if f.OWASP != "" {
				fmt.Printf("- **OWASP**: %s\n", f.OWASP)
			}
			fmt.Printf("- **Problem**: %s\n", f.Message)
			if f.Code != "" {
				fmt.Println("- **Code**:")
				fmt.Printf("  ```%s\n", detectLanguage(f.File))
				fmt.Printf("  %s\n", f.Code)
				fmt.Println("  ```")
			}
			fmt.Printf("- **Required Fix**: Fix the %s vulnerability described above.\n", f.Rule)
			fmt.Println()
		}
	}

	fmt.Println("---")
	fmt.Println()
	fmt.Println("## INSTRUCTIONS")
	fmt.Println()
	fmt.Println("For each issue above, output:")
	fmt.Println()
	fmt.Println("1. The exact code replacement (old -> new) in unified diff format")
	fmt.Println("2. A one-line explanation of the fix")
	fmt.Println()
	fmt.Println("Use this format:")
	fmt.Println()
	fmt.Println("```diff")
	fmt.Println("// file: path/to/file.ts:42")
	fmt.Println("- old code here")
	fmt.Println("+ new code here")
	fmt.Println("```")
}

func detectLanguage(path string) string {
	ext := strings.ToLower(path[strings.LastIndex(path, ".")+1:])
	switch ext {
	case "py":
		return "python"
	case "js":
		return "javascript"
	case "ts", "tsx":
		return "typescript"
	case "go":
		return "go"
	case "rs":
		return "rust"
	case "java":
		return "java"
	case "rb":
		return "ruby"
	case "php":
		return "php"
	case "yaml", "yml":
		return "yaml"
	case "toml":
		return "toml"
	case "json":
		return "json"
	default:
		return ""
	}
}

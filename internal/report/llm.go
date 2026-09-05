package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/KJyang-0114/sift/internal/core"
)

// RenderLLM outputs the report in an LLM-consumable format.
// This format is designed for pasting into LLMs (Claude, GPT, etc.) so they can generate fix code directly.
func RenderLLM(out io.Writer, findings []core.Finding, diagnostics []core.Diagnostic, target string) error {
	var buffer strings.Builder
	renderLLM(&buffer, findings, diagnostics, target)
	_, err := io.WriteString(out, buffer.String())
	return err
}

func renderLLM(w io.Writer, findings []core.Finding, diagnostics []core.Diagnostic, target string) {
	fmt.Fprintln(w, "# Code Issues Report")
	fmt.Fprintln(w, "Scan status:", (core.AnalysisResult{Diagnostics: diagnostics}).Status())
	renderDiagnostics(w, diagnostics)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "The following security and logic issues were found in `%s`.\n", safeDisplayTarget(target))
	fmt.Fprintln(w, "For each issue, provide a specific code fix.")
	fmt.Fprintln(w)

	if len(findings) == 0 {
		if (core.AnalysisResult{Diagnostics: diagnostics}).HasErrors() {
			fmt.Fprintln(w, "Scan incomplete. No findings were reported by completed analysis.")
		} else {
			fmt.Fprintln(w, "No issues found by the enabled analyzers.")
		}
		return
	}

	groups := core.GroupBySeverity(findings)
	order := []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityInfo}

	idx := 0
	for _, sev := range order {
		for _, f := range groups[sev] {
			idx++
			fmt.Fprintf(w, "## Issue %d [%s] %s\n", idx, strings.ToUpper(string(f.Severity)), f.Rule)
			fmt.Fprintln(w)
			fmt.Fprintf(w, "- **File**: `%s`\n", f.Location.Path)
			fmt.Fprintf(w, "- **Line**: %d\n", f.Location.Line)
			fmt.Fprintf(w, "- **Confidence**: %s\n", f.Confidence)
			if f.CWE != "" {
				fmt.Fprintf(w, "- **CWE**: %s\n", f.CWE)
			}
			if f.OWASP != "" {
				fmt.Fprintf(w, "- **OWASP**: %s\n", f.OWASP)
			}
			fmt.Fprintf(w, "- **Problem**: %s\n", f.Message)
			code := ""
			if len(f.Evidence) > 0 {
				code = f.Evidence[0].Snippet
			}
			if code != "" {
				fmt.Fprintln(w, "- **Code**:")
				fmt.Fprintf(w, "  ```%s\n", detectLanguage(f.Location.Path))
				fmt.Fprintf(w, "  %s\n", code)
				fmt.Fprintln(w, "  ```")
			}
			fmt.Fprintf(w, "- **Required Fix**: %s\n", f.Remediation)
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## INSTRUCTIONS")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "For each issue above, output:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "1. The exact code replacement (old -> new) in unified diff format")
	fmt.Fprintln(w, "2. A one-line explanation of the fix")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use this format:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "```diff")
	fmt.Fprintln(w, "// file: path/to/file.ts:42")
	fmt.Fprintln(w, "- old code here")
	fmt.Fprintln(w, "+ new code here")
	fmt.Fprintln(w, "```")
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

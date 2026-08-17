package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
	"golang.org/x/term"
)

// Terminal color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorOrange = "\033[38;5;208m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorWhite  = "\033[97m"
	colorBold   = "\033[1m"
)

var severityIcon = map[core.Severity]string{
	core.SeverityCritical: "🔴",
	core.SeverityHigh:     "🟡",
	core.SeverityMedium:   "🟠",
	core.SeverityLow:      "🔵",
	core.SeverityInfo:     "⚪",
}

// RenderTerminal outputs the scan report in color terminal format.
func RenderTerminal(findings []core.Finding, target string, duration time.Duration) {
	width := 80
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w < width {
		width = w
	}

	groups := core.GroupBySeverity(findings)
	critical := len(groups[core.SeverityCritical])
	high := len(groups[core.SeverityHigh])
	medium := len(groups[core.SeverityMedium])
	low := len(groups[core.SeverityLow])
	info := len(groups[core.SeverityInfo])

	printBar(width)
	printLine(width, fmt.Sprintf("🔍 Sift Scan Report — %s", time.Now().Format("2006-01-02 15:04:05")))
	printLine(width, fmt.Sprintf("Project: %s — Scan duration: %.1fs", safeDisplayTarget(target), duration.Seconds()))
	printBar(width)

	if len(findings) == 0 {
		printLine(width, "  ✅ No issues found. Your code is clean!")
		printBar(width)
		return
	}

	// Summary line
	summary := fmt.Sprintf("  %s Critical: %d  %s High: %d  %s Medium: %d  %s Low: %d  %s Info: %d",
		severityIcon[core.SeverityCritical], critical,
		severityIcon[core.SeverityHigh], high,
		severityIcon[core.SeverityMedium], medium,
		severityIcon[core.SeverityLow], low,
		severityIcon[core.SeverityInfo], info,
	)
	printLine(width, summary)
	printBar(width)
	fmt.Println()

	// Output sorted by severity
	order := []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityInfo}

	displayed := 0
	maxDisplay := 20

	for _, sev := range order {
		for _, f := range groups[sev] {
			if displayed >= maxDisplay {
				fmt.Printf("  %s... and %d more issue(s)%s\n", colorGray, len(findings)-maxDisplay, colorReset)
				fmt.Println()
				printBar(width)
				fmt.Printf("  %sFull report: sift scan . --format json%s\n", colorGray, colorReset)
				fmt.Printf("  %sSend to LLM for fixes: sift scan . --format llm | claude -p \"Fix all\"%s\n", colorGray, colorReset)
				return
			}

			renderFinding(f, displayed+1)
			displayed++
		}
	}

	printBar(width)
	fmt.Printf("  %sSend to LLM for fixes: sift scan . --format llm | claude -p \"Fix all\"%s\n", colorGray, colorReset)
}

func renderFinding(f core.Finding, idx int) {
	label := f.ID
	if label == "" {
		label = f.Rule
	}
	if label != "" {
		label = strings.ToUpper(label[:1]) + label[1:]
	}
	if len(label) > 60 {
		label = label[:57] + "..."
	}

	fmt.Printf("  %s %s%s%s\n", severityIcon[f.Severity], colorBold+colorWhite, label, colorReset)
	fmt.Printf("  %s────────────────────────────────────────────────%s\n", colorGray, colorReset)
	fmt.Printf("  %sFile:%s    %s:%d\n", colorGray, colorReset, f.Location.Path, f.Location.Line)

	code := ""
	if len(f.Evidence) > 0 {
		code = f.Evidence[0].Snippet
	}
	if code != "" {
		codePreview := strings.TrimSpace(code)
		if len(codePreview) > 100 {
			codePreview = codePreview[:97] + "..."
		}
		fmt.Printf("  %sCode:%s    %s\n", colorGray, colorReset, colorCyan+codePreview+colorReset)
	}

	fmt.Printf("  %sIssue:%s   %s\n", colorGray, colorReset, f.Message)
	fmt.Printf("  %sConfidence:%s %s\n", colorGray, colorReset, f.Confidence)

	if f.CWE != "" {
		fmt.Printf("  %sCWE:%s     %s\n", colorGray, colorReset, f.CWE)
	}
	fmt.Println()
}

func printBar(width int) {
	fmt.Println(strings.Repeat("─", width))
}

func printLine(width int, text string) {
	// Strip ANSI codes to calculate visible length
	clean := stripANSI(text)
	padding := width - len(clean)
	if padding < 0 {
		padding = 0
	}
	fmt.Printf("%s%s%s\n", text, strings.Repeat(" ", padding), colorReset)
}

func stripANSI(s string) string {
	result := s
	for {
		start := strings.Index(result, "\033[")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "m")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+1:]
	}
	return result
}

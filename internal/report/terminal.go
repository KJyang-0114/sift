package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/static"
	"golang.org/x/term"
)

// 終端顏色碼
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

var severityIcon = map[static.Severity]string{
	static.SeverityCritical: "🔴",
	static.SeverityHigh:     "🟡",
	static.SeverityMedium:   "🟠",
	static.SeverityLow:      "🔵",
	static.SeverityInfo:     "⚪",
}

// RenderTerminal 以彩色終端格式輸出掃描報告。
func RenderTerminal(findings []static.Finding, target string, duration time.Duration) {
	width := 80
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w < width {
		width = w
	}

	groups := static.GroupBySeverity(findings)
	critical := len(groups[static.SeverityCritical])
	high := len(groups[static.SeverityHigh])
	medium := len(groups[static.SeverityMedium])
	low := len(groups[static.SeverityLow])
	info := len(groups[static.SeverityInfo])

	printBar(width)
	printLine(width, fmt.Sprintf("🔍 Sift Scan Report — %s", time.Now().Format("2006-01-02 15:04:05")))
	printLine(width, fmt.Sprintf("Project: %s — Scan duration: %.1fs", target, duration.Seconds()))
	printBar(width)

	if len(findings) == 0 {
		printLine(width, "  ✅ No issues found. Your code is clean!")
		printBar(width)
		return
	}

	// 摘要列
	summary := fmt.Sprintf("  %s Critical: %d  %s High: %d  %s Medium: %d  %s Low: %d  %s Info: %d",
		severityIcon[static.SeverityCritical], critical,
		severityIcon[static.SeverityHigh], high,
		severityIcon[static.SeverityMedium], medium,
		severityIcon[static.SeverityLow], low,
		severityIcon[static.SeverityInfo], info,
	)
	printLine(width, summary)
	printBar(width)
	fmt.Println()

	// 按嚴重度排序輸出
	order := []static.Severity{static.SeverityCritical, static.SeverityHigh, static.SeverityMedium, static.SeverityLow, static.SeverityInfo}

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

func renderFinding(f static.Finding, idx int) {
	label := strings.ToUpper(f.ID[:1]) + f.ID[1:]
	if len(label) > 60 {
		label = label[:57] + "..."
	}

	fmt.Printf("  %s %s%s%s\n", severityIcon[f.Severity], colorBold+colorWhite, label, colorReset)
	fmt.Printf("  %s────────────────────────────────────────────────%s\n", colorGray, colorReset)
	fmt.Printf("  %sFile:%s    %s:%d\n", colorGray, colorReset, f.File, f.Line)

	if f.Code != "" {
		codePreview := strings.TrimSpace(f.Code)
		if len(codePreview) > 100 {
			codePreview = codePreview[:97] + "..."
		}
		fmt.Printf("  %sCode:%s    %s\n", colorGray, colorReset, colorCyan+codePreview+colorReset)
	}

	fmt.Printf("  %sIssue:%s   %s\n", colorGray, colorReset, f.Message)

	if f.CWE != "" {
		fmt.Printf("  %sCWE:%s     %s\n", colorGray, colorReset, f.CWE)
	}
	fmt.Println()
}

func printBar(width int) {
	fmt.Println(strings.Repeat("─", width))
}

func printLine(width int, text string) {
	// 去掉 ANSI 碼計算長度
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

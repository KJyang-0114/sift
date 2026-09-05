package report

import (
	"fmt"
	"io"
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
func RenderTerminal(out io.Writer, findings []core.Finding, diagnostics []core.Diagnostic, target string, duration time.Duration, color bool) error {
	width := 80
	file, isFile := out.(*os.File)
	isTerminal := isFile && term.IsTerminal(int(file.Fd()))
	if isTerminal {
		if size, _, err := term.GetSize(int(file.Fd())); err == nil && size > 0 && size < width {
			width = size
		}
	}
	var buffer strings.Builder
	renderTerminal(&buffer, findings, diagnostics, target, duration, width)
	text := buffer.String()
	if !color || !isTerminal {
		text = stripANSI(text)
	}
	_, err := io.WriteString(out, text)
	return err
}

func renderTerminal(w io.Writer, findings []core.Finding, diagnostics []core.Diagnostic, target string, duration time.Duration, width int) {

	groups := core.GroupBySeverity(findings)
	critical := len(groups[core.SeverityCritical])
	high := len(groups[core.SeverityHigh])
	medium := len(groups[core.SeverityMedium])
	low := len(groups[core.SeverityLow])
	info := len(groups[core.SeverityInfo])

	printBar(w, width)
	printLine(w, width, fmt.Sprintf("🔍 Sift Scan Report — %s", time.Now().Format("2006-01-02 15:04:05")))
	printLine(w, width, fmt.Sprintf("Project: %s — Scan duration: %.1fs", safeDisplayTarget(target), duration.Seconds()))
	printLine(w, width, "Scan status: "+(core.AnalysisResult{Diagnostics: diagnostics}).Status())
	renderDiagnostics(w, diagnostics)
	printBar(w, width)

	if len(findings) == 0 {
		if (core.AnalysisResult{Diagnostics: diagnostics}).HasErrors() {
			printLine(w, width, "  Scan incomplete. No findings were reported by completed analysis.")
		} else {
			printLine(w, width, "  No issues found by the enabled analyzers.")
		}
		printBar(w, width)
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
	printLine(w, width, summary)
	printBar(w, width)
	fmt.Fprintln(w)

	// Output sorted by severity
	order := []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityInfo}

	displayed := 0
	maxDisplay := 20

	for _, sev := range order {
		for _, f := range groups[sev] {
			if displayed >= maxDisplay {
				fmt.Fprintf(w, "  %s... and %d more issue(s)%s\n", colorGray, len(findings)-maxDisplay, colorReset)
				fmt.Fprintln(w)
				printBar(w, width)
				fmt.Fprintf(w, "  %sFull report: sift scan . --format json%s\n", colorGray, colorReset)
				fmt.Fprintf(w, "  %sSend to LLM for fixes: sift scan . --format llm | claude -p \"Fix all\"%s\n", colorGray, colorReset)
				return
			}

			renderFinding(w, f, displayed+1)
			displayed++
		}
	}

	printBar(w, width)
	fmt.Fprintf(w, "  %sSend to LLM for fixes: sift scan . --format llm | claude -p \"Fix all\"%s\n", colorGray, colorReset)
}

func renderFinding(w io.Writer, f core.Finding, idx int) {
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

	fmt.Fprintf(w, "  %s %s%s%s\n", severityIcon[f.Severity], colorBold+colorWhite, label, colorReset)
	fmt.Fprintf(w, "  %s────────────────────────────────────────────────%s\n", colorGray, colorReset)
	fmt.Fprintf(w, "  %sFile:%s    %s:%d\n", colorGray, colorReset, f.Location.Path, f.Location.Line)

	code := ""
	if len(f.Evidence) > 0 {
		code = f.Evidence[0].Snippet
	}
	if code != "" {
		codePreview := strings.TrimSpace(code)
		if len(codePreview) > 100 {
			codePreview = codePreview[:97] + "..."
		}
		fmt.Fprintf(w, "  %sCode:%s    %s\n", colorGray, colorReset, colorCyan+codePreview+colorReset)
	}

	fmt.Fprintf(w, "  %sIssue:%s   %s\n", colorGray, colorReset, f.Message)
	fmt.Fprintf(w, "  %sConfidence:%s %s\n", colorGray, colorReset, f.Confidence)

	if f.CWE != "" {
		fmt.Fprintf(w, "  %sCWE:%s     %s\n", colorGray, colorReset, f.CWE)
	}
	fmt.Fprintln(w)
}

func printBar(w io.Writer, width int) {
	fmt.Fprintln(w, strings.Repeat("─", width))
}

func printLine(w io.Writer, width int, text string) {
	// Strip ANSI codes to calculate visible length
	clean := stripANSI(text)
	padding := width - len(clean)
	if padding < 0 {
		padding = 0
	}
	fmt.Fprintf(w, "%s%s%s\n", text, strings.Repeat(" ", padding), colorReset)
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

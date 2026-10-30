package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

func TestHumanReportsHideSuppressedFindings(t *testing.T) {
	active := core.Finding{Rule: "active-rule", Message: "still open", Severity: core.SeverityHigh, Location: core.Location{Path: "a.py", Line: 1}}
	accepted := core.Finding{Rule: "accepted-rule", Message: "hidden-issue", Severity: core.SeverityCritical, Location: core.Location{Path: "b.py", Line: 2},
		Suppression: core.Suppression{Suppressed: true, Reason: "baseline: ok"}}
	findings := []core.Finding{active, accepted}

	var terminal bytes.Buffer
	renderTerminal(&terminal, findings, nil, "repo", 0, 120)
	if !strings.Contains(terminal.String(), "still open") || strings.Contains(terminal.String(), "hidden-issue") ||
		!strings.Contains(terminal.String(), "Suppressed: 1") {
		t.Fatalf("terminal:\n%s", terminal.String())
	}

	var llm bytes.Buffer
	renderLLM(&llm, findings, nil, "repo")
	if !strings.Contains(llm.String(), "still open") || strings.Contains(llm.String(), "hidden-issue") ||
		!strings.Contains(llm.String(), "1 accepted finding(s) are suppressed") {
		t.Fatalf("llm:\n%s", llm.String())
	}

	var onlyAccepted bytes.Buffer
	renderTerminal(&onlyAccepted, []core.Finding{accepted}, nil, "repo", 0, 120)
	if !strings.Contains(onlyAccepted.String(), "No issues found") {
		t.Fatalf("all-suppressed terminal:\n%s", onlyAccepted.String())
	}
}

package report

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

func reportFinding(t *testing.T, rule string, severity core.Severity) core.Finding {
	t.Helper()
	finding, err := core.NewFinding(core.FindingInput{
		Source: "test", Rule: rule, Message: "message " + rule,
		Severity: severity, Category: "security", Confidence: core.ConfidenceHigh,
		Location:    core.Location{Path: "src/app.go", Line: 7, Column: 2, EndLine: 7, EndColumn: 8},
		Evidence:    []core.Evidence{{Kind: core.EvidenceCode, Snippet: "danger()"}},
		Remediation: "Use the safe API.", HelpURI: "https://example.test/" + rule,
		StableKey: rule,
	})
	if err != nil {
		t.Fatal(err)
	}
	return finding
}

func TestEncodeJSONUsesV2EnvelopeSafeTargetAndEmptyArrays(t *testing.T) {
	now := time.Date(2026, 8, 17, 1, 2, 3, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "private-repository")
	data, err := encodeJSON(nil, nil, root, 1500*time.Millisecond, now)
	if err != nil {
		t.Fatal(err)
	}

	var got jsonReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != core.FindingSchemaVersion || got.Tool != "sift" {
		t.Fatalf("unexpected schema/tool: %#v", got)
	}
	if got.Target != "private-repository" || strings.Contains(string(data), filepath.Dir(root)) {
		t.Fatalf("target leaked an absolute host path: %s", data)
	}
	if got.Timestamp != "2026-08-17T01:02:03Z" || got.Duration != "1.50s" {
		t.Fatalf("unexpected deterministic metadata: %#v", got)
	}
	if got.Findings == nil || got.Diagnostics == nil {
		t.Fatal("findings or diagnostics encoded as null")
	}
}

func TestEncodeJSONCountsSeveritiesAndCarriesTypedDiagnostics(t *testing.T) {
	findings := []core.Finding{
		reportFinding(t, "critical", core.SeverityCritical),
		reportFinding(t, "high-1", core.SeverityHigh),
		reportFinding(t, "high-2", core.SeverityHigh),
		reportFinding(t, "medium", core.SeverityMedium),
		reportFinding(t, "low", core.SeverityLow),
		reportFinding(t, "info", core.SeverityInfo),
	}
	diagnostics := []core.Diagnostic{{
		Kind: core.DiagnosticIntegration, Severity: core.DiagnosticWarning,
		Code: "registry.unavailable", Source: "package-verifier", Message: "offline",
	}}

	data, err := encodeJSON(findings, diagnostics, "repo", time.Second, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var got jsonReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := jsonSummary{Total: 6, Critical: 1, High: 2, Medium: 1, Low: 1, Info: 1}
	if got.Summary != want {
		t.Fatalf("summary = %#v, want %#v", got.Summary, want)
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "registry.unavailable" {
		t.Fatalf("diagnostics = %#v", got.Diagnostics)
	}
}

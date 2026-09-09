package static

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

func TestParseSemgrepOutputBuildsFindingV2(t *testing.T) {
	root := t.TempDir()
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(map[string]any{
		"results": []any{map[string]any{
			"check_id": "sift.sql-injection",
			"path":     filepath.Join(root, "src", "app.go"),
			"start":    map[string]any{"line": 7, "col": 3, "offset": 10},
			"end":      map[string]any{"line": 7, "col": 18, "offset": 25},
			"extra": map[string]any{
				"message":  "User input reaches SQL",
				"severity": "WARNING",
				"lines":    "db.Query(input)",
				"metadata": map[string]any{"category": "security", "cwe": "CWE-89", "owasp": "A03:2021"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	findings, diagnostics := parseSemgrepOutput(output, request)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Source != "semgrep" || finding.Rule != "sift.sql-injection" {
		t.Fatalf("unexpected provenance: source=%q rule=%q", finding.Source, finding.Rule)
	}
	if finding.Location.Path != "src/app.go" || finding.Location.Line != 7 || finding.Location.EndColumn != 18 {
		t.Fatalf("unexpected location: %#v", finding.Location)
	}
	if finding.Confidence != core.ConfidenceHigh {
		t.Fatalf("confidence = %q, want high", finding.Confidence)
	}
	if len(finding.Evidence) != 1 || finding.Evidence[0].Kind != core.EvidenceCode || finding.Evidence[0].Snippet != "db.Query(input)" {
		t.Fatalf("unexpected evidence: %#v", finding.Evidence)
	}
	if finding.Remediation == "" || finding.Fingerprint == "" {
		t.Fatal("finding is missing remediation or fingerprint")
	}
}

func TestParseSemgrepPreservesErrorsAndSuccessfulFindings(t *testing.T) {
	request, err := core.NewScanRequest(t.TempDir(), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	output := []byte(`{"results":[{"check_id":"fixture","path":"app.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"kept","severity":"WARNING","lines":"x"}}],"errors":[{"code":3,"level":"warn","message":"could not parse file","path":"app.py"}]}`)
	findings, diagnostics := parseSemgrepOutput(output, request)
	if len(findings) != 1 || len(diagnostics) != 1 || diagnostics[0].Severity != core.DiagnosticError || diagnostics[0].Code != "semgrep.error.3" || diagnostics[0].Path != "app.py" {
		t.Fatalf("findings=%#v diagnostics=%#v", findings, diagnostics)
	}
}

func TestParseSemgrepRejectsMissingReport(t *testing.T) {
	request, err := core.NewScanRequest(t.TempDir(), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"", "garbage", "null", "{}", `{"results":null}`} {
		findings, diagnostics := parseSemgrepOutput([]byte(output), request)
		if len(findings) != 0 || len(diagnostics) != 1 || diagnostics[0].Code != "semgrep.invalid-output" {
			t.Fatalf("output=%q findings=%#v diagnostics=%#v", output, findings, diagnostics)
		}
	}
}

func TestBoundedOutputConsumesOverflowWithoutGrowing(t *testing.T) {
	buffer := &boundedOutput{limit: 8}
	for _, text := range []string{"first", " more text", "ignored"} {
		n, err := buffer.Write([]byte(text))
		if n != len(text) || err != nil {
			t.Fatalf("write=%d, %v", n, err)
		}
	}
	if buffer.buffer.String() != "first mo" || !buffer.truncated {
		t.Fatalf("buffer=%q truncated=%v", buffer.buffer.String(), buffer.truncated)
	}
}

func TestSemgrepDiagnosticBoundsMessageAndHidesRoot(t *testing.T) {
	root := t.TempDir()
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"results": []any{}, "errors": []any{map[string]any{"code": 2, "message": root + strings.Repeat("x", 4096), "path": "../outside.py"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, diagnostics := parseSemgrepOutput(data, request)
	if len(diagnostics) != 1 || len(diagnostics[0].Message) > core.MaxEvidenceSnippetBytes || strings.Contains(diagnostics[0].Message, root) || diagnostics[0].Path != "" {
		t.Fatalf("diagnostics=%#v", diagnostics)
	}
}

func TestParseSemgrepOutputRejectsEscapingLocation(t *testing.T) {
	root := t.TempDir()
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(map[string]any{
		"results": []any{map[string]any{
			"check_id": "sift.escape",
			"path":     filepath.Join(filepath.Dir(root), "outside.go"),
			"start":    map[string]any{"line": 1, "col": 1},
			"end":      map[string]any{"line": 1, "col": 2},
			"extra": map[string]any{
				"message": "outside", "severity": "ERROR", "lines": "secret",
				"metadata": map[string]any{"category": "security"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	findings, diagnostics := parseSemgrepOutput(output, request)
	if len(findings) != 0 {
		t.Fatalf("escaping finding was retained: %#v", findings)
	}
	if len(diagnostics) != 1 || diagnostics[0].Kind != core.DiagnosticTarget {
		t.Fatalf("diagnostics = %#v, want one target diagnostic", diagnostics)
	}
}

func TestEmbeddedRulesLoadOnEveryPlatform(t *testing.T) {
	if len(embeddedRules) == 0 {
		t.Fatal("embedded rule bundle is empty")
	}
	for name, rule := range embeddedRules {
		if rule == "" {
			t.Fatalf("empty embedded rule %s", name)
		}
	}
}

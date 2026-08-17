package agent

import (
	"path/filepath"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

func TestParseSemanticResultBuildsLowConfidenceEvidenceBackedFinding(t *testing.T) {
	root := t.TempDir()
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	modelOutput := `[{"severity":"high","line":2,"message":"user input reaches a command","category":"security"}]`
	source := "func safe() {}\nexec.Command(input)\n"

	findings, diagnostics := parseSemanticResult(modelOutput, request, filepath.Join(root, "cmd.go"), source)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Source != "llm-semantic" || finding.Confidence != core.ConfidenceLow {
		t.Fatalf("unexpected provenance/confidence: source=%q confidence=%q", finding.Source, finding.Confidence)
	}
	if finding.Location.Path != "cmd.go" || finding.Location.Line != 2 {
		t.Fatalf("unexpected location: %#v", finding.Location)
	}
	if len(finding.Evidence) != 2 || finding.Evidence[0].Kind != core.EvidenceCode || finding.Evidence[0].Snippet != "exec.Command(input)" || finding.Evidence[1].Kind != core.EvidenceModel {
		t.Fatalf("unexpected evidence: %#v", finding.Evidence)
	}
}

func TestParseSemanticResultReportsMalformedModelOutput(t *testing.T) {
	root := t.TempDir()
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	findings, diagnostics := parseSemanticResult("[not-json]", request, filepath.Join(root, "cmd.go"), "source")
	if len(findings) != 0 {
		t.Fatalf("findings = %#v", findings)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "llm.invalid-output" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

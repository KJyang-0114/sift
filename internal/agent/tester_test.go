package agent

import (
	"path/filepath"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/sandbox"
)

func TestExecutionFindingsCarryBoundedExecutionEvidence(t *testing.T) {
	root := t.TempDir()
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	execution := &sandbox.Result{ExitCode: 1, Stderr: "assertion failed", Error: "pytest failed"}

	findings, diagnostics := executionFindings(request, filepath.Join(root, "app.py"), execution)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Source != "test-generator" || finding.Confidence != core.ConfidenceMedium {
		t.Fatalf("unexpected provenance/confidence: %#v", finding)
	}
	if len(finding.Evidence) != 1 || finding.Evidence[0].Kind != core.EvidenceExecution || finding.Evidence[0].Snippet != "assertion failed" {
		t.Fatalf("unexpected evidence: %#v", finding.Evidence)
	}
}

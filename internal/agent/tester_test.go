package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/sandbox"
)

type recordingTestClient struct {
	calls int
}

func (c *recordingTestClient) Name() string { return "recording" }

func (c *recordingTestClient) Chat(context.Context, string, string) (string, error) {
	c.calls++
	return "```python\nassert True\n```", nil
}

func TestTestGeneratorDoesNotExecuteWhenPolicyDisabled(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("value = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &recordingTestClient{}
	tg := &TestGenerator{client: client, cfg: config.Default()}
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	result := tg.Analyze(context.Background(), request)
	if client.calls != 0 {
		t.Fatalf("LLM calls = %d, want 0; result=%#v", client.calls, result)
	}
	if len(result.Findings) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "test-generator.execution-disabled" {
		t.Fatalf("result = %#v, want policy diagnostic and no execution finding", result)
	}
	if result.HasErrors() {
		t.Fatal("disabled execution must not fail analysis")
	}

	tg.cfg.Execution.Enabled = true
	result = tg.Analyze(context.Background(), request)
	if client.calls != 0 || len(result.Findings) != 0 || !result.HasErrors() || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "test-generator.executor-unavailable" {
		t.Fatalf("enabled execution must fail closed without a container: %#v", result)
	}
}

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

func TestGeneratorExportsOptInArtifact(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("value = 1"), 0600); err != nil {
		t.Fatal(err)
	}
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Execution.Generate = true
	client := &recordingTestClient{}
	result := (&TestGenerator{client: client, cfg: cfg}).Analyze(context.Background(), request)
	if result.HasErrors() || client.calls != 1 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "test-generator.exported" {
		t.Fatalf("result=%#v calls=%d", result, client.calls)
	}
	files, err := filepath.Glob(filepath.Join(root, ".sift", "generated-tests", "test_app_*.py"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	content, err := os.ReadFile(files[0])
	if err != nil || string(content) != "assert True\n" {
		t.Fatalf("content=%q err=%v", content, err)
	}
}

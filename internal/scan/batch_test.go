package scan

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

func TestParseBatchResultsUsesFindingV2AndRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "app.go")
	outside := filepath.Join(filepath.Dir(root), "outside.go")
	modelOutput := `{"file":` + quoteJSON(inside) + `,"line":4,"severity":"high","category":"security","message":"inside"}` + "\n" +
		`{"file":` + quoteJSON(outside) + `,"line":1,"severity":"high","category":"security","message":"outside"}`

	findings, diagnostics := parseBatchResults(modelOutput, request)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	if findings[0].Source != "llm-batch" || findings[0].Confidence != core.ConfidenceLow || findings[0].Location.Path != "app.go" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if len(diagnostics) != 1 || diagnostics[0].Kind != core.DiagnosticTarget {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func quoteJSON(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

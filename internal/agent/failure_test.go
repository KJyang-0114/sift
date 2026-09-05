package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

type failingModel struct{ err error }

func (model failingModel) Name() string                                         { return "fixture" }
func (model failingModel) Chat(context.Context, string, string) (string, error) { return "", model.err }

func TestConfiguredModelFailuresMakeAnalysisPartial(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "demo.py"), []byte("print(1)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	model := failingModel{err: errors.New("provider unavailable")}
	for _, analyzer := range []core.Analyzer{&SemanticAnalyzer{client: model}, &TestGenerator{client: model}, &TestGenerator{client: failingModel{}}} {
		result := analyzer.Analyze(context.Background(), request)
		if len(result.Findings) != 0 || !result.HasErrors() || len(result.Diagnostics) != 1 {
			t.Fatalf("%s failure = %#v", analyzer.Name(), result)
		}
	}
}

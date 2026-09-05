package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
)

type brokenWriter struct{ err error }

func (w brokenWriter) Write([]byte) (int, error) { return 0, w.err }

func TestAllFormatsReturnOutputFailures(t *testing.T) {
	want := errors.New("output pipe closed")
	for _, format := range []string{"json", "sarif", "terminal", "llm"} {
		t.Run(format, func(t *testing.T) {
			err := NewEngine(config.Default()).Render(brokenWriter{want}, nil, nil, "repo", time.Second, format)
			if !errors.Is(err, want) {
				t.Fatalf("write error = %v, want %v", err, want)
			}
		})
	}
}

func TestReportsDoNotCallIncompleteScanClean(t *testing.T) {
	diagnostics := []core.Diagnostic{{Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
		Code: "fixture.failed", Source: "fixture", Message: "analyzer did not finish"}}
	for _, format := range []string{"terminal", "llm", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := NewEngine(config.Default()).Render(&output, nil, diagnostics, "repo", time.Second, format); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if !strings.Contains(text, "fixture.failed") || strings.Contains(text, "Your code is clean") || strings.Contains(text, "No issues found") {
				t.Fatalf("misleading report: %s", text)
			}
			if format == "sarif" {
				if !strings.Contains(text, `"executionSuccessful": false`) {
					t.Fatal(text)
				}
			} else if !strings.Contains(text, "partial") {
				t.Fatal(text)
			}
		})
	}
}

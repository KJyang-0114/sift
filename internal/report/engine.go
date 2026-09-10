package report

import (
	"fmt"
	"io"
	"time"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
)

// Engine manages report rendering for all output formats.
type Engine struct {
	cfg *config.Config
}

// NewEngine creates a new report engine.
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

// Render outputs the report in the specified format.
func (e *Engine) Render(w io.Writer, findings []core.Finding, diagnostics []core.Diagnostic, target string, duration time.Duration, format string) error {
	switch format {
	case "json":
		return RenderJSON(w, findings, diagnostics, target, duration)
	case "llm":
		return RenderLLM(w, findings, diagnostics, target)
	case "sarif":
		return RenderSARIF(w, findings, diagnostics, target)
	case "terminal":
		return RenderTerminal(w, findings, diagnostics, target, duration, e.cfg.Output.Color)
	}
	return fmt.Errorf("unsupported output format %q", format)
}

// ValidFormat prevents invalid configuration from starting a scan.
func ValidFormat(format string) bool {
	switch format {
	case "terminal", "json", "sarif", "llm":
		return true
	}
	return false
}

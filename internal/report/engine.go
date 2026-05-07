package report

import (
	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/static"
	"time"
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
func (e *Engine) Render(findings []static.Finding, target string, duration time.Duration, format string) {
	switch format {
	case "json":
		RenderJSON(findings, target, duration)
	case "llm":
		RenderLLM(findings, target)
	case "sarif":
		RenderSARIF(findings, target)
	default:
		RenderTerminal(findings, target, duration)
	}
}

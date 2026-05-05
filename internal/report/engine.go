package report

import (
	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/static"
	"time"
)

// Engine 管理所有輸出格式的報告引擎。
type Engine struct {
	cfg *config.Config
}

// NewEngine 建立報告引擎。
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

// Render 根據指定格式輸出報告。
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

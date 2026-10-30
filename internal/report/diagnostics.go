package report

import (
	"fmt"
	"io"

	"github.com/KJyang-0114/sift/internal/core"
)

// Text renderers call this with their in-memory report buffer.
func renderDiagnostics(w io.Writer, diagnostics []core.Diagnostic) {
	if len(diagnostics) == 0 {
		return
	}
	fmt.Fprintln(w, "Diagnostics:")
	for _, diagnostic := range diagnostics {
		fmt.Fprintf(w, "- %s [%s] %s: %s\n", diagnostic.Severity, diagnostic.Code, diagnostic.Source, diagnostic.Message)
	}
}

// splitSuppressed separates findings that still need attention from accepted ones.
func splitSuppressed(findings []core.Finding) ([]core.Finding, int) {
	active := make([]core.Finding, 0, len(findings))
	for _, finding := range findings {
		if !finding.Suppression.Suppressed {
			active = append(active, finding)
		}
	}
	return active, len(findings) - len(active)
}

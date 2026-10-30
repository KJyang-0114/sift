package policy

import (
	"fmt"
	"strings"

	"github.com/KJyang-0114/sift/internal/core"
)

var severityRank = map[core.Severity]int{
	core.SeverityInfo: 1, core.SeverityLow: 2, core.SeverityMedium: 3, core.SeverityHigh: 4, core.SeverityCritical: 5,
}

var confidenceRank = map[core.Confidence]int{
	core.ConfidenceLow: 1, core.ConfidenceMedium: 2, core.ConfidenceHigh: 3,
}

// Gate blocks a scan when an unsuppressed finding reaches both thresholds.
// A zero FailOn disables the gate, keeping findings advisory.
type Gate struct {
	FailOn        core.Severity
	MinConfidence core.Confidence
}

// ParseGate validates --fail-on and --min-confidence values.
func ParseGate(failOn, minConfidence string) (Gate, error) {
	// Medium by default: low-confidence heuristics report findings but do not block.
	gate := Gate{MinConfidence: core.ConfidenceMedium}
	switch value := core.Severity(strings.ToLower(strings.TrimSpace(failOn))); {
	case value == "" || value == "none":
	case value.Valid():
		gate.FailOn = value
	default:
		return Gate{}, fmt.Errorf("invalid --fail-on %q (critical|high|medium|low|info|none)", failOn)
	}
	if value := core.Confidence(strings.ToLower(strings.TrimSpace(minConfidence))); value != "" {
		if !value.Valid() {
			return Gate{}, fmt.Errorf("invalid --min-confidence %q (high|medium|low)", minConfidence)
		}
		gate.MinConfidence = value
	}
	return gate, nil
}

// Enabled reports whether the gate can fail a scan.
func (g Gate) Enabled() bool {
	return g.FailOn != ""
}

// Blocking returns unsuppressed findings at or above both thresholds.
func (g Gate) Blocking(findings []core.Finding) []core.Finding {
	if !g.Enabled() {
		return nil
	}
	var blocking []core.Finding
	for _, finding := range findings {
		if finding.Suppression.Suppressed {
			continue
		}
		if severityRank[finding.Severity] >= severityRank[g.FailOn] && confidenceRank[finding.Confidence] >= confidenceRank[g.MinConfidence] {
			blocking = append(blocking, finding)
		}
	}
	return blocking
}

package static

import (
	"time"
)

// Severity defines the severity level of an issue.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding represents an issue found by static analysis.
type Finding struct {
	ID       string   `json:"id"`
	Rule     string   `json:"rule"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	Code     string   `json:"code"`
	CWE      string   `json:"cwe,omitempty"`
	OWASP    string   `json:"owasp,omitempty"`
}

// Analyzer defines the interface for a static analyzer.
type Analyzer interface {
	Name() string
	Analyze(target string) ([]Finding, error)
}

// Result represents the outcome of a complete static scan.
type Result struct {
	Analyzer  string        `json:"analyzer"`
	Target    string        `json:"target"`
	Findings  []Finding     `json:"findings"`
	Duration  time.Duration `json:"duration"`
	Error     error         `json:"error,omitempty"`
}

// FilterBySeverity filters findings by severity level.
func FilterBySeverity(findings []Finding, minSeverity Severity) []Finding {
	weights := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	threshold := weights[minSeverity]
	var filtered []Finding
	for _, f := range findings {
		if weights[f.Severity] >= threshold {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GroupBySeverity groups findings by severity level.
func GroupBySeverity(findings []Finding) map[Severity][]Finding {
	groups := make(map[Severity][]Finding)
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	return groups
}

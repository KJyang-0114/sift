package static

import (
	"time"
)

// Severity 定義問題嚴重程度。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding 代表靜態分析找到的一個問題。
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

// Analyzer 定義靜態分析器的介面。
type Analyzer interface {
	Name() string
	Analyze(target string) ([]Finding, error)
}

// Result 是一次完整靜態掃描的結果。
type Result struct {
	Analyzer  string        `json:"analyzer"`
	Target    string        `json:"target"`
	Findings  []Finding     `json:"findings"`
	Duration  time.Duration `json:"duration"`
	Error     error         `json:"error,omitempty"`
}

// FilterBySeverity 依嚴重等級過濾 findings。
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

// GroupBySeverity 按嚴重等級分組。
func GroupBySeverity(findings []Finding) map[Severity][]Finding {
	groups := make(map[Severity][]Finding)
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	return groups
}

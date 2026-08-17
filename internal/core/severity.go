package core

// Severity defines the normalized impact level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Valid reports whether the severity is part of the Finding v2 contract.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

// Confidence expresses how strongly the available evidence supports a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Valid reports whether the confidence is part of the Finding v2 contract.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	default:
		return false
	}
}

// FilterBySeverity filters findings by severity while preserving input order.
func FilterBySeverity(findings []Finding, minimum Severity) []Finding {
	weights := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	threshold := weights[minimum]
	filtered := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if weights[finding.Severity] >= threshold {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// GroupBySeverity groups findings by severity.
func GroupBySeverity(findings []Finding) map[Severity][]Finding {
	groups := make(map[Severity][]Finding)
	for _, finding := range findings {
		groups[finding.Severity] = append(groups[finding.Severity], finding)
	}
	return groups
}

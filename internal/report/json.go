package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/KJyang-0114/sift/internal/static"
)

type jsonReport struct {
	Tool      string          `json:"tool"`
	Version   string          `json:"version"`
	Target    string          `json:"target"`
	Timestamp string          `json:"timestamp"`
	Duration  string          `json:"duration"`
	Summary   jsonSummary     `json:"summary"`
	Findings  []static.Finding `json:"findings"`
}

type jsonSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// RenderJSON outputs the scan report in JSON format.
func RenderJSON(findings []static.Finding, target string, duration time.Duration) {
	groups := static.GroupBySeverity(findings)

	report := jsonReport{
		Tool:      "sift",
		Target:    target,
		Timestamp: time.Now().Format(time.RFC3339),
		Duration:  fmt.Sprintf("%.2fs", duration.Seconds()),
		Summary: jsonSummary{
			Total:    len(findings),
			Critical: len(groups[static.SeverityCritical]),
			High:     len(groups[static.SeverityHigh]),
			Medium:   len(groups[static.SeverityMedium]),
			Low:      len(groups[static.SeverityLow]),
			Info:     len(groups[static.SeverityInfo]),
		},
		Findings: findings,
	}

	if report.Findings == nil {
		report.Findings = []static.Finding{}
	}

	out, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(out))
}

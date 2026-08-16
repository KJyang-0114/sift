package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/KJyang-0114/sift/internal/static"
)

type jsonReport struct {
	Tool      string           `json:"tool"`
	Version   string           `json:"version"`
	Target    string           `json:"target"`
	Timestamp string           `json:"timestamp"`
	Duration  string           `json:"duration"`
	Summary   jsonSummary      `json:"summary"`
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
	out, err := encodeJSON(findings, target, duration, time.Now())
	if err != nil {
		fmt.Printf("{\"error\":%q}\n", err.Error())
		return
	}
	fmt.Println(string(out))
}

func encodeJSON(findings []static.Finding, target string, duration time.Duration, now time.Time) ([]byte, error) {
	groups := static.GroupBySeverity(findings)

	report := jsonReport{
		Tool:      "sift",
		Target:    target,
		Timestamp: now.Format(time.RFC3339),
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

	return json.MarshalIndent(report, "", "  ")
}

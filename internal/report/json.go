package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

type jsonReport struct {
	SchemaVersion string            `json:"schema_version"`
	Tool          string            `json:"tool"`
	Version       string            `json:"version"`
	Target        string            `json:"target"`
	Timestamp     string            `json:"timestamp"`
	Duration      string            `json:"duration"`
	Summary       jsonSummary       `json:"summary"`
	Findings      []core.Finding    `json:"findings"`
	Diagnostics   []core.Diagnostic `json:"diagnostics"`
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
func RenderJSON(findings []core.Finding, diagnostics []core.Diagnostic, target string, duration time.Duration) {
	out, err := encodeJSON(findings, diagnostics, target, duration, time.Now())
	if err != nil {
		fmt.Printf("{\"error\":%q}\n", err.Error())
		return
	}
	fmt.Println(string(out))
}

func encodeJSON(findings []core.Finding, diagnostics []core.Diagnostic, target string, duration time.Duration, now time.Time) ([]byte, error) {
	groups := core.GroupBySeverity(findings)

	report := jsonReport{
		SchemaVersion: core.FindingSchemaVersion,
		Tool:          "sift",
		Version:       "0.2",
		Target:        safeDisplayTarget(target),
		Timestamp:     now.Format(time.RFC3339),
		Duration:      fmt.Sprintf("%.2fs", duration.Seconds()),
		Summary: jsonSummary{
			Total:    len(findings),
			Critical: len(groups[core.SeverityCritical]),
			High:     len(groups[core.SeverityHigh]),
			Medium:   len(groups[core.SeverityMedium]),
			Low:      len(groups[core.SeverityLow]),
			Info:     len(groups[core.SeverityInfo]),
		},
		Findings:    findings,
		Diagnostics: diagnostics,
	}

	if report.Findings == nil {
		report.Findings = []core.Finding{}
	}
	if report.Diagnostics == nil {
		report.Diagnostics = []core.Diagnostic{}
	}

	return json.MarshalIndent(report, "", "  ")
}

func safeDisplayTarget(target string) string {
	clean := filepath.Clean(target)
	if filepath.IsAbs(clean) {
		return filepath.Base(clean)
	}
	return filepath.ToSlash(clean)
}

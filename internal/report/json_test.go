package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/static"
)

func TestEncodeJSONUsesDeterministicMetadataAndEmptyArray(t *testing.T) {
	now := time.Date(2026, 8, 17, 1, 2, 3, 0, time.UTC)
	data, err := encodeJSON(nil, "repo", 1500*time.Millisecond, now)
	if err != nil {
		t.Fatal(err)
	}

	var got jsonReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Tool != "sift" {
		t.Fatalf("tool = %q, want sift", got.Tool)
	}
	if got.Target != "repo" {
		t.Fatalf("target = %q, want repo", got.Target)
	}
	if got.Timestamp != "2026-08-17T01:02:03Z" {
		t.Fatalf("timestamp = %q, want fixed RFC3339 value", got.Timestamp)
	}
	if got.Duration != "1.50s" {
		t.Fatalf("duration = %q, want 1.50s", got.Duration)
	}
	if got.Findings == nil {
		t.Fatal("findings encoded as null, want an empty array")
	}
	if got.Summary.Total != 0 {
		t.Fatalf("summary total = %d, want 0", got.Summary.Total)
	}
}

func TestEncodeJSONCountsEverySeverity(t *testing.T) {
	findings := []static.Finding{
		{ID: "critical", Severity: static.SeverityCritical},
		{ID: "high-1", Severity: static.SeverityHigh},
		{ID: "high-2", Severity: static.SeverityHigh},
		{ID: "medium", Severity: static.SeverityMedium},
		{ID: "low", Severity: static.SeverityLow},
		{ID: "info", Severity: static.SeverityInfo},
	}

	data, err := encodeJSON(findings, "repo", time.Second, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var got jsonReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := jsonSummary{Total: 6, Critical: 1, High: 2, Medium: 1, Low: 1, Info: 1}
	if got.Summary != want {
		t.Fatalf("summary = %#v, want %#v", got.Summary, want)
	}
}

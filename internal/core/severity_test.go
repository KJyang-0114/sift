package core

import "testing"

func TestSeverityAndConfidenceValidation(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{name: string(SeverityCritical), valid: SeverityCritical.Valid()},
		{name: string(SeverityHigh), valid: SeverityHigh.Valid()},
		{name: string(SeverityMedium), valid: SeverityMedium.Valid()},
		{name: string(SeverityLow), valid: SeverityLow.Valid()},
		{name: string(SeverityInfo), valid: SeverityInfo.Valid()},
		{name: "unknown severity", valid: Severity("urgent").Valid()},
		{name: string(ConfidenceHigh), valid: ConfidenceHigh.Valid()},
		{name: string(ConfidenceMedium), valid: ConfidenceMedium.Valid()},
		{name: string(ConfidenceLow), valid: ConfidenceLow.Valid()},
		{name: "unknown confidence", valid: Confidence("certain").Valid()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.name != "unknown severity" && tt.name != "unknown confidence"
			if tt.valid != want {
				t.Fatalf("valid = %v, want %v", tt.valid, want)
			}
		})
	}
}

func TestFilterBySeverityIncludesThresholdAndPreservesOrder(t *testing.T) {
	findings := []Finding{
		{ID: "high-1", Severity: SeverityHigh},
		{ID: "info", Severity: SeverityInfo},
		{ID: "critical", Severity: SeverityCritical},
		{ID: "high-2", Severity: SeverityHigh},
	}

	got := FilterBySeverity(findings, SeverityHigh)
	want := []string{"high-1", "critical", "high-2"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("result[%d].ID = %q, want %q", i, got[i].ID, want[i])
		}
	}
}

func TestGroupBySeverityReturnsNonNilMapForEmptyInput(t *testing.T) {
	if got := GroupBySeverity(nil); got == nil {
		t.Fatal("GroupBySeverity returned a nil map")
	}
}

package static

import "testing"

func TestFilterBySeverityIncludesThresholdAndHigher(t *testing.T) {
	findings := []Finding{
		{ID: "critical", Severity: SeverityCritical},
		{ID: "high", Severity: SeverityHigh},
		{ID: "medium", Severity: SeverityMedium},
		{ID: "low", Severity: SeverityLow},
		{ID: "info", Severity: SeverityInfo},
	}

	got := FilterBySeverity(findings, SeverityMedium)
	want := []string{"critical", "high", "medium"}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("finding %d = %q, want %q", i, got[i].ID, want[i])
		}
	}
}

func TestFilterBySeverityPreservesInputOrder(t *testing.T) {
	findings := []Finding{
		{ID: "second-high", Severity: SeverityHigh},
		{ID: "critical", Severity: SeverityCritical},
		{ID: "first-high", Severity: SeverityHigh},
	}

	got := FilterBySeverity(findings, SeverityHigh)
	want := []string{"second-high", "critical", "first-high"}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("finding %d = %q, want %q", i, got[i].ID, want[i])
		}
	}
}

func TestGroupBySeveritySeparatesEveryLevel(t *testing.T) {
	findings := []Finding{
		{ID: "critical", Severity: SeverityCritical},
		{ID: "high-1", Severity: SeverityHigh},
		{ID: "high-2", Severity: SeverityHigh},
		{ID: "medium", Severity: SeverityMedium},
		{ID: "low", Severity: SeverityLow},
		{ID: "info", Severity: SeverityInfo},
	}

	got := GroupBySeverity(findings)
	wantCounts := map[Severity]int{
		SeverityCritical: 1,
		SeverityHigh:     2,
		SeverityMedium:   1,
		SeverityLow:      1,
		SeverityInfo:     1,
	}
	for severity, want := range wantCounts {
		if len(got[severity]) != want {
			t.Errorf("%s count = %d, want %d", severity, len(got[severity]), want)
		}
	}
}

func TestGroupBySeverityEmptyInput(t *testing.T) {
	got := GroupBySeverity(nil)
	if got == nil {
		t.Fatal("GroupBySeverity returned a nil map")
	}
	if len(got) != 0 {
		t.Fatalf("got %d groups, want 0", len(got))
	}
}

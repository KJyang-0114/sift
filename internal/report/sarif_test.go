package report

import (
	"encoding/json"
	"testing"

	"github.com/KJyang-0114/sift/internal/static"
)

type sarifDocumentForTest struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func decodeSARIFForTest(t *testing.T, data []byte) sarifDocumentForTest {
	t.Helper()
	var got sarifDocumentForTest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestEncodeSARIFEmitsGitHubCompatibleStructure(t *testing.T) {
	findings := []static.Finding{
		{Rule: "sift.rule", Message: "first", Severity: static.SeverityHigh, File: "src/app.go", Line: 7, Column: 0},
		{Rule: "sift.rule", Message: "second", Severity: static.SeverityMedium, File: "src/app.go", Line: 9, Column: 4},
	}

	data, err := encodeSARIF(findings)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeSARIFForTest(t, data)
	if got.Version != "2.1.0" || got.Schema == "" {
		t.Fatalf("unexpected SARIF metadata: version=%q schema=%q", got.Version, got.Schema)
	}
	if len(got.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(got.Runs))
	}
	run := got.Runs[0]
	if run.Tool.Driver.Name != "Sift" {
		t.Fatalf("driver name = %q, want Sift", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("rules = %d, want one descriptor for duplicate rule IDs", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	if run.Results[0].Level != "error" || run.Results[1].Level != "warning" {
		t.Fatalf("levels = %q, %q; want error, warning", run.Results[0].Level, run.Results[1].Level)
	}
	location := run.Results[0].Locations[0].PhysicalLocation
	if location.ArtifactLocation.URI != "src/app.go" || location.Region.StartLine != 7 || location.Region.StartColumn != 1 {
		t.Fatalf("unexpected first location: %#v", location)
	}
}

func TestEncodeSARIFMapsNonBlockingLevels(t *testing.T) {
	findings := []static.Finding{
		{Rule: "low", Severity: static.SeverityLow},
		{Rule: "info", Severity: static.SeverityInfo},
	}
	data, err := encodeSARIF(findings)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeSARIFForTest(t, data)
	if got.Runs[0].Results[0].Level != "note" || got.Runs[0].Results[1].Level != "none" {
		t.Fatalf("levels = %#v, want note and none", got.Runs[0].Results)
	}
}

func TestEncodeSARIFUsesEmptyArrays(t *testing.T) {
	data, err := encodeSARIF(nil)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeSARIFForTest(t, data)
	if got.Runs[0].Results == nil {
		t.Fatal("results encoded as null, want an empty array")
	}
	if got.Runs[0].Tool.Driver.Rules == nil {
		t.Fatal("rules encoded as null, want an empty array")
	}
}

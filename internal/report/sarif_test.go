package report

import (
	"encoding/json"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

type sarifDocumentForTest struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID      string `json:"id"`
					HelpURI string `json:"helpUri"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID              string            `json:"ruleId"`
			Level               string            `json:"level"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          struct {
				Source      string `json:"source"`
				Confidence  string `json:"confidence"`
				Remediation string `json:"remediation"`
			} `json:"properties"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
						EndLine     int `json:"endLine"`
						EndColumn   int `json:"endColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
		Invocations []struct {
			Notifications []struct {
				Level string `json:"level"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
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

func TestEncodeSARIFEmitsV2IdentityPropertiesAndDiagnostics(t *testing.T) {
	first := reportFinding(t, "sift.rule", core.SeverityHigh)
	second := reportFinding(t, "sift.rule", core.SeverityMedium)
	second.Location.Line = 9
	diagnostics := []core.Diagnostic{{
		Kind: core.DiagnosticIntegration, Severity: core.DiagnosticWarning,
		Code: "registry.unavailable", Source: "package-verifier", Message: "offline",
	}}

	data, err := encodeSARIF([]core.Finding{first, second}, diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeSARIFForTest(t, data)
	if got.Version != "2.1.0" || got.Schema == "" || len(got.Runs) != 1 {
		t.Fatalf("unexpected SARIF metadata: %#v", got)
	}
	run := got.Runs[0]
	if run.Tool.Driver.Name != "Sift" || len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].HelpURI == "" {
		t.Fatalf("unexpected driver/rules: %#v", run.Tool.Driver)
	}
	if len(run.Results) != 2 || run.Results[0].Level != "error" || run.Results[1].Level != "warning" {
		t.Fatalf("unexpected results: %#v", run.Results)
	}
	result := run.Results[0]
	if result.PartialFingerprints["sift/v2"] != first.Fingerprint {
		t.Fatalf("fingerprint = %#v", result.PartialFingerprints)
	}
	if result.Properties.Source != first.Source || result.Properties.Confidence != string(first.Confidence) || result.Properties.Remediation != first.Remediation {
		t.Fatalf("properties = %#v", result.Properties)
	}
	location := result.Locations[0].PhysicalLocation
	if location.ArtifactLocation.URI != "src/app.go" || location.Region.StartLine != 7 || location.Region.StartColumn != 2 || location.Region.EndColumn != 8 {
		t.Fatalf("unexpected location: %#v", location)
	}
	if len(run.Invocations) != 1 || len(run.Invocations[0].Notifications) != 1 || run.Invocations[0].Notifications[0].Level != "warning" {
		t.Fatalf("diagnostic notifications = %#v", run.Invocations)
	}
}

func TestEncodeSARIFUsesEmptyArrays(t *testing.T) {
	data, err := encodeSARIF(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeSARIFForTest(t, data)
	if got.Runs[0].Results == nil || got.Runs[0].Tool.Driver.Rules == nil || got.Runs[0].Invocations == nil || got.Runs[0].Invocations[0].Notifications == nil {
		t.Fatalf("SARIF contains null collections: %#v", got.Runs[0])
	}
}

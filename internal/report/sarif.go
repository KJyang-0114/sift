package report

import (
	"encoding/json"
	"fmt"

	"github.com/KJyang-0114/sift/internal/core"
)

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifMessage         `json:"message,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	RelatedLocations    []sarifLocation    `json:"relatedLocations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Properties          map[string]any     `json:"properties"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifReportingDescriptor struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifToolComponent struct {
	Name  string                     `json:"name"`
	Rules []sarifReportingDescriptor `json:"rules"`
}

type sarifNotification struct {
	Level      string         `json:"level"`
	Message    sarifMessage   `json:"message"`
	Properties map[string]any `json:"properties"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
}

type sarifRun struct {
	Tool struct {
		Driver sarifToolComponent `json:"driver"`
	} `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// RenderSARIF outputs the report in SARIF 2.1.0 format.
func RenderSARIF(findings []core.Finding, diagnostics []core.Diagnostic, target string) {
	out, err := encodeSARIF(findings, diagnostics)
	if err != nil {
		fmt.Printf("{\"error\":%q}\n", err.Error())
		return
	}
	fmt.Println(string(out))
}

func encodeSARIF(findings []core.Finding, diagnostics []core.Diagnostic) ([]byte, error) {
	driver := sarifToolComponent{Name: "Sift", Rules: []sarifReportingDescriptor{}}
	ruleSet := make(map[string]bool)
	results := []sarifResult{}

	for _, finding := range findings {
		if !ruleSet[finding.Rule] {
			ruleSet[finding.Rule] = true
			driver.Rules = append(driver.Rules, sarifReportingDescriptor{
				ID: finding.Rule, ShortDescription: sarifMessage{Text: finding.Message}, HelpURI: finding.HelpURI,
			})
		}

		related := make([]sarifLocation, 0, len(finding.RelatedLocations))
		for _, relatedLocation := range finding.RelatedLocations {
			related = append(related, makeSARIFLocation(relatedLocation, "Related location"))
		}
		item := sarifResult{
			RuleID: finding.Rule, Level: mapSARIFLevel(finding.Severity), Message: sarifMessage{Text: finding.Message},
			Locations: []sarifLocation{makeSARIFLocation(finding.Location, "")}, RelatedLocations: related,
			PartialFingerprints: map[string]string{"sift/v2": finding.Fingerprint},
			Properties: map[string]any{
				"id": finding.ID, "schemaVersion": finding.SchemaVersion, "source": finding.Source,
				"category": finding.Category, "confidence": finding.Confidence,
				"remediation": finding.Remediation, "suppressed": finding.Suppression.Suppressed,
			},
		}
		if finding.Suppression.Suppressed {
			item.Suppressions = []sarifSuppression{{Kind: "external", Justification: finding.Suppression.Reason}}
		}
		results = append(results, item)
	}

	notifications := make([]sarifNotification, 0, len(diagnostics))
	executionSuccessful := true
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == core.DiagnosticError {
			executionSuccessful = false
		}
		notifications = append(notifications, sarifNotification{
			Level: mapDiagnosticSARIFLevel(diagnostic.Severity), Message: sarifMessage{Text: diagnostic.Message},
			Properties: map[string]any{
				"code": diagnostic.Code, "kind": diagnostic.Kind, "source": diagnostic.Source,
			},
		})
	}

	run := sarifRun{Results: results, Invocations: []sarifInvocation{{
		ExecutionSuccessful: executionSuccessful, ToolExecutionNotifications: notifications,
	}}}
	run.Tool.Driver = driver
	document := sarifDocument{
		Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []sarifRun{run},
	}
	return json.MarshalIndent(document, "", "  ")
}

func makeSARIFLocation(value core.Location, description string) sarifLocation {
	location := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: value.Path},
		Region: sarifRegion{
			StartLine: value.Line, StartColumn: value.Column,
			EndLine: value.EndLine, EndColumn: value.EndColumn,
		},
	}}
	if description != "" {
		location.Message = &sarifMessage{Text: description}
	}
	return location
}

func mapSARIFLevel(severity core.Severity) string {
	switch severity {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	case core.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

func mapDiagnosticSARIFLevel(severity core.DiagnosticSeverity) string {
	switch severity {
	case core.DiagnosticError:
		return "error"
	case core.DiagnosticWarning:
		return "warning"
	default:
		return "note"
	}
}

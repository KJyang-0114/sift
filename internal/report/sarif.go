package report

import (
	"encoding/json"
	"fmt"

	"github.com/KJyang-0114/sift/internal/static"
)

// RenderSARIF outputs the report in SARIF 2.1.0 format (GitHub Code Scanning compatible).
func RenderSARIF(findings []static.Finding, target string) {
	type artifactLocation struct {
		URI string `json:"uri"`
	}

	type region struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn"`
	}

	type physicalLocation struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
		Region            region           `json:"region"`
	}

	type location struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	}

	type message struct {
		Text string `json:"text"`
	}

	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   message    `json:"message"`
		Locations []location `json:"locations"`
	}

	type reportingDescriptor struct {
		ID               string  `json:"id"`
		ShortDescription message `json:"shortDescription"`
	}

	type toolComponent struct {
		Name  string                 `json:"name"`
		Rules []reportingDescriptor  `json:"rules"`
	}

	sarif := struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver toolComponent `json:"driver"`
			} `json:"tool"`
			Results []result `json:"results"`
		} `json:"runs"`
	}{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	driver := toolComponent{
		Name: "Sift",
	}

	ruleSet := make(map[string]bool)
	var results []result

	for _, f := range findings {
		if !ruleSet[f.Rule] {
			ruleSet[f.Rule] = true
			driver.Rules = append(driver.Rules, reportingDescriptor{
				ID:               f.Rule,
				ShortDescription: message{Text: f.Message},
			})
		}

		level := mapSARIFLevel(f.Severity)
		results = append(results, result{
			RuleID:  f.Rule,
			Level:   level,
			Message: message{Text: f.Message},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: f.File},
					Region: region{
						StartLine:   f.Line,
						StartColumn: max(f.Column, 1),
					},
				},
			}},
		})
	}

	sarif.Runs = append(sarif.Runs, struct {
		Tool struct {
			Driver toolComponent `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}{
		Tool:    struct{ Driver toolComponent `json:"driver"` }{Driver: driver},
		Results: results,
	})

	out, _ := json.MarshalIndent(sarif, "", "  ")
	fmt.Println(string(out))
}

func mapSARIFLevel(sev static.Severity) string {
	switch sev {
	case static.SeverityCritical, static.SeverityHigh:
		return "error"
	case static.SeverityMedium:
		return "warning"
	case static.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

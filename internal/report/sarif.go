package report

import (
	"encoding/json"
	"fmt"

	"github.com/KJyang-0114/sift/internal/static"
)

// RenderSARIF 以 SARIF 2.1.0 格式輸出報告（GitHub Code Scanning 相容）。
func RenderSARIF(findings []static.Finding, target string) {
	type physicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn"`
		} `json:"region"`
	}

	type result struct {
		RuleID    string             `json:"ruleId"`
		Level     string             `json:"level"`
		Message   struct{ Text string } `json:"message"`
		Locations []physicalLocation `json:"locations"`
	}

	type reportingDescriptor struct {
		ID               string `json:"id"`
		ShortDescription struct{ Text string } `json:"shortDescription"`
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
				ID: f.Rule,
				ShortDescription: struct{ Text string }{
					Text: f.Message,
				},
			})
		}

		level := mapSARIFLevel(f.Severity)
		results = append(results, result{
			RuleID:  f.Rule,
			Level:   level,
			Message: struct{ Text string }{Text: f.Message},
			Locations: []physicalLocation{{
				ArtifactLocation: struct{ URI string `json:"uri"` }{URI: f.File},
				Region: struct {
					StartLine   int `json:"startLine"`
					StartColumn int `json:"startColumn"`
				}{StartLine: f.Line, StartColumn: max(f.Column, 1)},
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

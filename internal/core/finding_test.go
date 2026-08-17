package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func validFindingInput() FindingInput {
	return FindingInput{
		Source:      "semgrep",
		Rule:        "sift.sql-injection",
		Message:     "User input reaches a SQL query",
		Severity:    SeverityHigh,
		Category:    "security",
		Confidence:  ConfidenceHigh,
		Location:    Location{Path: `internal\\db\\query.go`, Line: 42, Column: 7},
		Evidence:    []Evidence{{Kind: EvidenceCode, Snippet: `db.Query(userInput)`}},
		Remediation: "Use a parameterized query.",
		HelpURI:     "https://example.test/rules/sql-injection",
		CWE:         "CWE-89",
		OWASP:       "A03:2021",
		StableKey:   "call-expression:42",
	}
}

func TestNewFindingBuildsStableSafeIdentity(t *testing.T) {
	in := validFindingInput()
	first, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	in.Location.Path = "internal/db/query.go"
	second, err := NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding with slash path: %v", err)
	}

	if first.SchemaVersion != FindingSchemaVersion {
		t.Fatalf("schema version = %q, want %q", first.SchemaVersion, FindingSchemaVersion)
	}
	if first.Location.Path != "internal/db/query.go" {
		t.Fatalf("normalized path = %q", first.Location.Path)
	}
	if first.ID == "" || first.Fingerprint == "" {
		t.Fatalf("missing stable identity: id=%q fingerprint=%q", first.ID, first.Fingerprint)
	}
	if first.ID != second.ID || first.Fingerprint != second.Fingerprint {
		t.Fatalf("path separator changed identity: first=%q/%q second=%q/%q", first.ID, first.Fingerprint, second.ID, second.Fingerprint)
	}
	if !strings.HasPrefix(first.Fingerprint, "sha256:") || len(first.Fingerprint) != len("sha256:")+64 {
		t.Fatalf("unexpected fingerprint format %q", first.Fingerprint)
	}
	if first.RelatedLocations == nil || first.Evidence == nil {
		t.Fatal("serialized collection fields must be non-nil")
	}
}

func TestNewFindingFingerprintIgnoresEvidenceAndRemediation(t *testing.T) {
	in := validFindingInput()
	first, err := NewFinding(in)
	if err != nil {
		t.Fatal(err)
	}

	in.Evidence[0].Snippet = "secret-token-should-not-affect-identity"
	in.Remediation = "A revised remediation"
	second, err := NewFinding(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("sensitive or presentation data changed fingerprint: %q != %q", first.Fingerprint, second.Fingerprint)
	}
}

func TestNewFindingRejectsInvalidInput(t *testing.T) {
	longEvidence := strings.Repeat("x", MaxEvidenceSnippetBytes+1)
	tests := []struct {
		name   string
		mutate func(*FindingInput)
	}{
		{name: "missing source", mutate: func(in *FindingInput) { in.Source = "" }},
		{name: "missing rule", mutate: func(in *FindingInput) { in.Rule = "" }},
		{name: "missing message", mutate: func(in *FindingInput) { in.Message = "" }},
		{name: "invalid severity", mutate: func(in *FindingInput) { in.Severity = "urgent" }},
		{name: "invalid confidence", mutate: func(in *FindingInput) { in.Confidence = "certain" }},
		{name: "absolute unix path", mutate: func(in *FindingInput) { in.Location.Path = "/home/user/project/main.go" }},
		{name: "absolute windows path", mutate: func(in *FindingInput) { in.Location.Path = `C:\\Users\\User\\project\\main.go` }},
		{name: "escaping path", mutate: func(in *FindingInput) { in.Location.Path = "../outside.go" }},
		{name: "missing path", mutate: func(in *FindingInput) { in.Location.Path = "" }},
		{name: "negative line", mutate: func(in *FindingInput) { in.Location.Line = -1 }},
		{name: "oversized evidence", mutate: func(in *FindingInput) { in.Evidence[0].Snippet = longEvidence }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validFindingInput()
			tt.mutate(&in)
			if _, err := NewFinding(in); err == nil {
				t.Fatal("NewFinding succeeded, want error")
			}
		})
	}
}

func TestFindingJSONNeverContainsHostRootOrStableKey(t *testing.T) {
	in := validFindingInput()
	in.StableKey = `C:\\Users\\User\\private\\secret-token`
	finding, err := NewFinding(in)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{`C:\\Users\\User`, "secret-token", "stable_key"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("serialized finding contains forbidden data %q: %s", forbidden, text)
		}
	}
}

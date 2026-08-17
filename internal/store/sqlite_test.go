package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

func TestStoreRoundTripsFindingV2(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	finding, err := core.NewFinding(core.FindingInput{
		Source: "semgrep", Rule: "sift.rule", Message: "message",
		Severity: core.SeverityHigh, Category: "security", Confidence: core.ConfidenceHigh,
		Location:    core.Location{Path: "src/app.go", Line: 3, Column: 4, EndLine: 3, EndColumn: 10},
		Evidence:    []core.Evidence{{Kind: core.EvidenceCode, Snippet: "danger()"}},
		Remediation: "Use the safe API.", HelpURI: "https://example.test/rule",
		Suppression: core.Suppression{Suppressed: true, Reason: "accepted risk"}, StableKey: "stable",
	})
	if err != nil {
		t.Fatal(err)
	}

	scanID, err := store.SaveScan("repo", time.Second, []core.Finding{finding}, 1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetScanFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if got[0].ID != finding.ID || got[0].Fingerprint != finding.Fingerprint || got[0].Location != finding.Location || got[0].Confidence != finding.Confidence || got[0].Suppression != finding.Suppression {
		t.Fatalf("round trip mismatch:\n got  %#v\n want %#v", got[0], finding)
	}
	if len(got[0].Evidence) != 1 || got[0].Evidence[0] != finding.Evidence[0] {
		t.Fatalf("evidence mismatch: %#v", got[0].Evidence)
	}
}

func TestStoreMigratesV1SchemaWithoutDroppingRows(t *testing.T) {
	root := t.TempDir()
	dbDir := filepath.Join(root, ".sift")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dbDir, "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, started_at DATETIME NOT NULL, duration_ms INTEGER, total_findings INTEGER DEFAULT 0, files_scanned INTEGER DEFAULT 0)`,
		`CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL, category TEXT, file TEXT NOT NULL, line INTEGER, message TEXT, code_snippet TEXT, cwe TEXT, owasp TEXT, fixed INTEGER DEFAULT 0, fixed_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`INSERT INTO scans (id, target, started_at) VALUES (1, 'repo', datetime('now'))`,
		`INSERT INTO findings (scan_id, rule_id, severity, category, file, line, message, code_snippet) VALUES (1, 'legacy.rule', 'high', 'security', 'legacy.go', 5, 'legacy message', 'danger()')`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	findings, err := store.GetScanFindings(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Rule != "legacy.rule" || findings[0].Source != "legacy" || findings[0].Location.Path != "legacy.go" {
		t.Fatalf("legacy row was not migrated: %#v", findings)
	}
	if findings[0].ID == "" || findings[0].Fingerprint == "" || len(findings[0].Evidence) == 0 {
		t.Fatalf("legacy row lacks synthesized v2 fields: %#v", findings[0])
	}
}

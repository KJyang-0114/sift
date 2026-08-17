package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
	_ "modernc.org/sqlite"
)

// Store provides SQLite-based persistent storage for findings.
// Enterprise features: history queries, trend analysis, fix tracking.
type Store struct {
	db *sql.DB
}

// NewStore creates or opens the SQLite database.
func NewStore(projectRoot string) (*Store, error) {
	dbDir := filepath.Join(projectRoot, ".sift")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	dbPath := filepath.Join(dbDir, "findings.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite single writer
	db.SetConnMaxLifetime(0)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	return s, nil
}

// migrate creates the necessary tables.
func (s *Store) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			started_at DATETIME NOT NULL,
			duration_ms INTEGER,
			total_findings INTEGER DEFAULT 0,
			files_scanned INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			finding_uid TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL DEFAULT '',
			schema_version TEXT NOT NULL DEFAULT '2',
			source TEXT NOT NULL DEFAULT 'legacy',
			rule_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			category TEXT,
			confidence TEXT NOT NULL DEFAULT 'low',
			file TEXT NOT NULL,
			line INTEGER,
			column_number INTEGER DEFAULT 0,
			end_line INTEGER DEFAULT 0,
			end_column INTEGER DEFAULT 0,
			message TEXT,
			code_snippet TEXT,
			related_locations_json TEXT NOT NULL DEFAULT '[]',
			evidence_json TEXT NOT NULL DEFAULT '[]',
			remediation TEXT NOT NULL DEFAULT '',
			help_uri TEXT,
			cwe TEXT,
			owasp TEXT,
			suppressed INTEGER DEFAULT 0,
			suppression_reason TEXT,
			fixed INTEGER DEFAULT 0,
			fixed_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_fixed ON findings(fixed)`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migration failed (%s): %w", q[:30], err)
		}
	}
	return s.ensureFindingColumns()
}

func (s *Store) ensureFindingColumns() error {
	rows, err := s.db.Query(`PRAGMA table_info(findings)`)
	if err != nil {
		return err
	}
	existing := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}

	columns := []struct {
		name       string
		definition string
	}{
		{"finding_uid", `TEXT NOT NULL DEFAULT ''`},
		{"fingerprint", `TEXT NOT NULL DEFAULT ''`},
		{"schema_version", `TEXT NOT NULL DEFAULT '1'`},
		{"source", `TEXT NOT NULL DEFAULT 'legacy'`},
		{"confidence", `TEXT NOT NULL DEFAULT 'low'`},
		{"column_number", `INTEGER DEFAULT 0`},
		{"end_line", `INTEGER DEFAULT 0`},
		{"end_column", `INTEGER DEFAULT 0`},
		{"related_locations_json", `TEXT NOT NULL DEFAULT '[]'`},
		{"evidence_json", `TEXT NOT NULL DEFAULT '[]'`},
		{"remediation", `TEXT NOT NULL DEFAULT ''`},
		{"help_uri", `TEXT`},
		{"suppressed", `INTEGER DEFAULT 0`},
		{"suppression_reason", `TEXT`},
	}
	for _, column := range columns {
		if existing[column.name] {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE findings ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
			return fmt.Errorf("add findings.%s: %w", column.name, err)
		}
	}
	return nil
}

// SaveScan saves a scan and all its findings.
func (s *Store) SaveScan(target string, duration time.Duration, findings []core.Finding, filesScanned int) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Create scan record
	result, err := tx.Exec(
		`INSERT INTO scans (target, started_at, duration_ms, total_findings, files_scanned)
		 VALUES (?, datetime('now'), ?, ?, ?)`,
		safeStoredTarget(target), duration.Milliseconds(), len(findings), filesScanned,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to save scan record: %w", err)
	}

	scanID, _ := result.LastInsertId()

	// Save each finding
	stmt, err := tx.Prepare(
		`INSERT INTO findings (
			scan_id, finding_uid, fingerprint, schema_version, source, rule_id, severity, category, confidence,
			file, line, column_number, end_line, end_column, message, code_snippet,
			related_locations_json, evidence_json, remediation, help_uri, cwe, owasp, suppressed, suppression_reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, f := range findings {
		code := ""
		if len(f.Evidence) > 0 {
			code = f.Evidence[0].Snippet
		}
		if len(code) > 500 {
			code = code[:500]
		}
		relatedJSON, err := json.Marshal(f.RelatedLocations)
		if err != nil {
			return 0, fmt.Errorf("encode related locations: %w", err)
		}
		evidenceJSON, err := json.Marshal(f.Evidence)
		if err != nil {
			return 0, fmt.Errorf("encode evidence: %w", err)
		}
		_, err = stmt.Exec(
			scanID, f.ID, f.Fingerprint, f.SchemaVersion, f.Source, f.Rule, string(f.Severity), f.Category, string(f.Confidence),
			f.Location.Path, f.Location.Line, f.Location.Column, f.Location.EndLine, f.Location.EndColumn, f.Message, code,
			string(relatedJSON), string(evidenceJSON), f.Remediation, f.HelpURI, f.CWE, f.OWASP,
			f.Suppression.Suppressed, f.Suppression.Reason,
		)
		if err != nil {
			return 0, fmt.Errorf("failed to save finding: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return scanID, nil
}

// GetScanFindings returns all findings for a specific scan.
func (s *Store) GetScanFindings(scanID int64) ([]core.Finding, error) {
	rows, err := s.db.Query(
		`SELECT finding_uid, fingerprint, schema_version, source, rule_id, severity, category, confidence,
			file, line, column_number, end_line, end_column, message, code_snippet,
			related_locations_json, evidence_json, remediation, help_uri, cwe, owasp, suppressed, suppression_reason
		 FROM findings WHERE scan_id = ? ORDER BY severity, file, line`, scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanFindings(rows)
}

// GetUnfixedFindings returns all unfixed findings.
func (s *Store) GetUnfixedFindings() ([]core.Finding, error) {
	rows, err := s.db.Query(
		`SELECT finding_uid, fingerprint, schema_version, source, rule_id, severity, category, confidence,
			file, line, column_number, end_line, end_column, message, code_snippet,
			related_locations_json, evidence_json, remediation, help_uri, cwe, owasp, suppressed, suppression_reason
		 FROM findings WHERE fixed = 0 ORDER BY severity DESC, created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanFindings(rows)
}

// MarkFixed marks a finding as fixed.
func (s *Store) MarkFixed(findingID int64) error {
	_, err := s.db.Exec(`UPDATE findings SET fixed = 1, fixed_at = datetime('now') WHERE id = ?`, findingID)
	return err
}

// Stats returns overall statistics.
func (s *Store) Stats() (map[string]int, error) {
	stats := make(map[string]int)

	rows := []struct {
		query string
		key   string
	}{
		{`SELECT COUNT(*) FROM scans`, "total_scans"},
		{`SELECT COUNT(*) FROM findings`, "total_findings"},
		{`SELECT COUNT(*) FROM findings WHERE fixed = 0`, "unfixed"},
		{`SELECT COUNT(*) FROM findings WHERE severity = 'critical'`, "critical"},
		{`SELECT COUNT(*) FROM findings WHERE severity = 'high'`, "high"},
		{`SELECT COUNT(*) FROM findings WHERE severity = 'medium'`, "medium"},
	}

	for _, r := range rows {
		var count int
		if err := s.db.QueryRow(r.query).Scan(&count); err != nil {
			continue
		}
		stats[r.key] = count
	}

	return stats, nil
}

// RecentScans returns recent scan records.
func (s *Store) RecentScans(limit int) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(
		`SELECT id, target, started_at, duration_ms, total_findings, files_scanned
		 FROM scans ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var target string
		var startedAt string
		var durationMs, totalFindings, filesScanned int
		if err := rows.Scan(&id, &target, &startedAt, &durationMs, &totalFindings, &filesScanned); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"id": id, "target": target, "started_at": startedAt,
			"duration_s": float64(durationMs) / 1000,
			"findings":   totalFindings, "files": filesScanned,
		})
	}

	return results, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func scanFindings(rows *sql.Rows) ([]core.Finding, error) {
	findings := []core.Finding{}
	for rows.Next() {
		var findingID, fingerprint, schemaVersion, source, ruleID, severity, confidence, file, message string
		var category, codeSnippet, relatedJSON, evidenceJSON, remediation, helpURI, cwe, owasp, suppressionReason sql.NullString
		var line, column, endLine, endColumn sql.NullInt64
		var suppressed bool

		if err := rows.Scan(
			&findingID, &fingerprint, &schemaVersion, &source, &ruleID, &severity, &category, &confidence,
			&file, &line, &column, &endLine, &endColumn, &message, &codeSnippet,
			&relatedJSON, &evidenceJSON, &remediation, &helpURI, &cwe, &owasp, &suppressed, &suppressionReason,
		); err != nil {
			return nil, err
		}

		if findingID == "" || fingerprint == "" || schemaVersion != core.FindingSchemaVersion {
			legacy, err := legacyFinding(ruleID, severity, category.String, file, int(line.Int64), message, codeSnippet.String, cwe.String, owasp.String)
			if err != nil {
				return nil, err
			}
			findings = append(findings, legacy)
			continue
		}

		related := []core.Location{}
		if relatedJSON.String != "" {
			if err := json.Unmarshal([]byte(relatedJSON.String), &related); err != nil {
				return nil, fmt.Errorf("decode related locations: %w", err)
			}
		}
		evidence := []core.Evidence{}
		if evidenceJSON.String != "" {
			if err := json.Unmarshal([]byte(evidenceJSON.String), &evidence); err != nil {
				return nil, fmt.Errorf("decode evidence: %w", err)
			}
		}
		findings = append(findings, core.Finding{
			SchemaVersion: schemaVersion, ID: findingID, Fingerprint: fingerprint,
			Source: source, Rule: ruleID, Message: message, Severity: core.Severity(severity),
			Category: category.String, Confidence: core.Confidence(confidence),
			Location: core.Location{
				Path: file, Line: int(line.Int64), Column: int(column.Int64),
				EndLine: int(endLine.Int64), EndColumn: int(endColumn.Int64),
			},
			RelatedLocations: related, Evidence: evidence, Remediation: remediation.String,
			HelpURI: helpURI.String, CWE: cwe.String, OWASP: owasp.String,
			Suppression: core.Suppression{Suppressed: suppressed, Reason: suppressionReason.String},
		})
	}
	return findings, nil
}

func legacyFinding(rule, severity, category, file string, line int, message, code, cwe, owasp string) (core.Finding, error) {
	if !core.Severity(severity).Valid() {
		severity = string(core.SeverityMedium)
	}
	if category == "" {
		category = "legacy"
	}
	if strings.TrimSpace(message) == "" {
		message = "Imported legacy finding"
	}
	path := safeLegacyPath(file)
	evidence := core.Evidence{Kind: core.EvidenceOther, Snippet: code, Description: "Imported from a Finding v1 history row."}
	return core.NewFinding(core.FindingInput{
		Source: "legacy", Rule: rule, Message: message, Severity: core.Severity(severity),
		Category: category, Confidence: core.ConfidenceLow, Location: core.Location{Path: path, Line: line},
		Evidence:    []core.Evidence{evidence},
		Remediation: "Review and remediate this imported legacy finding.",
		CWE:         cwe, OWASP: owasp, StableKey: fmt.Sprintf("%d:%s", line, message),
	})
}

func safeLegacyPath(file string) string {
	file = strings.TrimSpace(file)
	if filepath.IsAbs(file) || (len(file) >= 2 && file[1] == ':') {
		file = filepath.Base(file)
	}
	file = filepath.ToSlash(filepath.Clean(file))
	if file == "." || file == ".." || strings.HasPrefix(file, "../") {
		return "legacy-unknown"
	}
	return file
}

func safeStoredTarget(target string) string {
	if filepath.IsAbs(target) {
		return filepath.Base(filepath.Clean(target))
	}
	return filepath.ToSlash(filepath.Clean(target))
}

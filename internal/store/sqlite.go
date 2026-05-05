package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KJyang-0114/sift/internal/static"
	_ "modernc.org/sqlite"
)

// Store 提供基於 SQLite 的 findings 持久化儲存。
// 企業級功能：歷史記錄查詢、趨勢分析、修復追蹤。
type Store struct {
	db *sql.DB
}

// NewStore 建立或開啟 SQLite 資料庫。
func NewStore(projectRoot string) (*Store, error) {
	dbDir := filepath.Join(projectRoot, ".sift")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		return nil, fmt.Errorf("建立資料庫目錄失敗: %w", err)
	}

	dbPath := filepath.Join(dbDir, "findings.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("開啟資料庫失敗: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite 單寫入者
	db.SetConnMaxLifetime(0)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("資料庫遷移失敗: %w", err)
	}

	return s, nil
}

// migrate 建立必要的資料表。
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
			rule_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			category TEXT,
			file TEXT NOT NULL,
			line INTEGER,
			message TEXT,
			code_snippet TEXT,
			cwe TEXT,
			owasp TEXT,
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
			return fmt.Errorf("遷移失敗 (%s): %w", q[:30], err)
		}
	}
	return nil
}

// SaveScan 儲存一次掃描及其所有 findings。
func (s *Store) SaveScan(target string, duration time.Duration, findings []static.Finding, filesScanned int) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// 建立掃描記錄
	result, err := tx.Exec(
		`INSERT INTO scans (target, started_at, duration_ms, total_findings, files_scanned)
		 VALUES (?, datetime('now'), ?, ?, ?)`,
		target, duration.Milliseconds(), len(findings), filesScanned,
	)
	if err != nil {
		return 0, fmt.Errorf("儲存掃描記錄失敗: %w", err)
	}

	scanID, _ := result.LastInsertId()

	// 儲存每個 finding
	stmt, err := tx.Prepare(
		`INSERT INTO findings (scan_id, rule_id, severity, category, file, line, message, code_snippet, cwe, owasp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, f := range findings {
		code := f.Code
		if len(code) > 500 {
			code = code[:500]
		}
		_, err := stmt.Exec(scanID, f.Rule, string(f.Severity), f.Category, f.File, f.Line, f.Message, code, f.CWE, f.OWASP)
		if err != nil {
			return 0, fmt.Errorf("儲存 finding 失敗: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return scanID, nil
}

// GetScanFindings 取得特定掃描的所有 findings。
func (s *Store) GetScanFindings(scanID int64) ([]static.Finding, error) {
	rows, err := s.db.Query(
		`SELECT rule_id, severity, category, file, line, message, code_snippet, cwe, owasp
		 FROM findings WHERE scan_id = ? ORDER BY severity, file, line`, scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanFindings(rows)
}

// GetUnfixedFindings 取得所有未修復的 findings。
func (s *Store) GetUnfixedFindings() ([]static.Finding, error) {
	rows, err := s.db.Query(
		`SELECT rule_id, severity, category, file, line, message, code_snippet, cwe, owasp
		 FROM findings WHERE fixed = 0 ORDER BY severity DESC, created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanFindings(rows)
}

// MarkFixed 標記 finding 為已修復。
func (s *Store) MarkFixed(findingID int64) error {
	_, err := s.db.Exec(`UPDATE findings SET fixed = 1, fixed_at = datetime('now') WHERE id = ?`, findingID)
	return err
}

// Stats 回傳整體統計資訊。
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

// RecentScans 取得最近的掃描記錄。
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
			"findings": totalFindings, "files": filesScanned,
		})
	}

	return results, nil
}

// Close 關閉資料庫連線。
func (s *Store) Close() error {
	return s.db.Close()
}

func scanFindings(rows *sql.Rows) ([]static.Finding, error) {
	var findings []static.Finding
	for rows.Next() {
		var ruleID, severity, file, message string
		var category, codeSnippet, cwe, owasp sql.NullString
		var line sql.NullInt64

		if err := rows.Scan(&ruleID, &severity, &category, &file, &line, &message, &codeSnippet, &cwe, &owasp); err != nil {
			continue
		}

		findings = append(findings, static.Finding{
			Rule:     ruleID,
			Severity: static.Severity(severity),
			Category: category.String,
			File:     file,
			Line:     int(line.Int64),
			Message:  message,
			Code:     codeSnippet.String,
			CWE:      cwe.String,
			OWASP:    owasp.String,
		})
	}
	return findings, nil
}

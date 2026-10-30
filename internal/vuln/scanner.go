// Package vuln matches exactly-versioned lockfile dependencies against public
// vulnerability advisories (OSV.dev) and the CISA Known Exploited Vulnerabilities catalog.
package vuln

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/securepath"
)

const (
	ruleVulnerable = "sift.vulnerable-dependency"
	ruleMalicious  = "sift.malicious-package"
)

var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, "__pycache__": true, "dist": true,
	"target": true, "venv": true, ".venv": true, "site-packages": true,
}

// Scanner is the dependency vulnerability analyzer.
type Scanner struct {
	feeds feedClient
}

var _ core.Analyzer = (*Scanner)(nil)

// NewScanner creates a scanner backed by the public OSV.dev API and CISA KEV feed.
func NewScanner() *Scanner {
	return newScanner(&http.Client{Timeout: 30 * time.Second}, defaultOSVURL, defaultKEVURL)
}

func newScanner(client *http.Client, osvURL, kevURL string) *Scanner {
	return &Scanner{feeds: feedClient{http: client, osvURL: osvURL, kevURL: kevURL, retryDelay: 500 * time.Millisecond}}
}

// Name returns the analyzer name.
func (s *Scanner) Name() string {
	return "vulnerability-db"
}

// Analyze resolves lockfile dependencies and reports published advisories affecting them.
// No network request is made when the targets contain no supported lockfile.
func (s *Scanner) Analyze(ctx context.Context, request core.ScanRequest) core.AnalysisResult {
	result := core.AnalysisResult{Findings: []core.Finding{}, Diagnostics: []core.Diagnostic{}}
	diagnose := func(kind core.DiagnosticKind, severity core.DiagnosticSeverity, code, path string, err error) {
		result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
			Kind: kind, Severity: severity, Code: code, Source: s.Name(), Message: err.Error(), Path: path, Cause: err,
		})
	}

	deps := s.collect(request, diagnose)
	if len(deps) == 0 {
		return result
	}

	unique := map[string]Dependency{}
	for _, dep := range deps {
		unique[dep.key()] = dep
	}
	queries := make([]Dependency, 0, len(unique))
	for _, dep := range unique {
		queries = append(queries, dep)
	}
	sort.Slice(queries, func(i, j int) bool { return queries[i].key() < queries[j].key() })

	advisories, err := s.feeds.queryOSV(ctx, queries)
	if err != nil {
		diagnose(core.DiagnosticIntegration, core.DiagnosticError, "osv.unavailable", "",
			fmt.Errorf("unable to check %d dependencies for known vulnerabilities: %w", len(queries), err))
		return result
	}

	idSet := map[string]bool{}
	for _, ids := range advisories {
		for _, id := range ids {
			idSet[id] = true
		}
	}
	if len(idSet) == 0 {
		return result
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	vulns, failures := s.feeds.fetchVulns(ctx, ids)
	if len(failures) > 0 {
		failed := make([]string, 0, len(failures))
		for id := range failures {
			failed = append(failed, id)
		}
		sort.Strings(failed)
		diagnose(core.DiagnosticIntegration, core.DiagnosticError, "osv.unavailable", "",
			fmt.Errorf("unable to load %d advisory details (%s): %w", len(failed), strings.Join(failed, ", "), failures[failed[0]]))
	}

	var kev map[string]kevEntry
	if hasCVE(vulns) {
		kev, err = s.feeds.fetchKEV(ctx)
		if err != nil {
			diagnose(core.DiagnosticIntegration, core.DiagnosticWarning, "kev.unavailable", "",
				fmt.Errorf("exploitation status unknown; findings are not prioritized by CISA KEV: %w", err))
		}
	}

	for _, dep := range deps {
		for _, vuln := range mergeAliases(advisories[dep.key()], vulns) {
			if vuln.Withdrawn != "" {
				continue
			}
			finding, err := buildFinding(s.Name(), dep, vuln, kev)
			if err != nil {
				diagnose(core.DiagnosticAnalyzer, core.DiagnosticError, "vulnerability-db.invalid-finding", dep.Path, err)
				continue
			}
			result.Findings = append(result.Findings, finding)
		}
	}
	return result
}

// collect walks targets for supported lockfiles. Reads are rooted so symlinks cannot escape.
func (s *Scanner) collect(request core.ScanRequest, diagnose func(core.DiagnosticKind, core.DiagnosticSeverity, string, string, error)) []Dependency {
	var deps []Dependency
	seen := map[string]bool{}
	for _, target := range request.AbsoluteTargets() {
		err := filepath.WalkDir(target, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				if path != target && skipDirs[entry.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			parse := parserFor(entry.Name())
			if parse == nil || !entry.Type().IsRegular() {
				return nil
			}
			relative, err := request.RelativePath(path)
			if err != nil || seen[relative] {
				return nil
			}
			seen[relative] = true
			data, err := securepath.ReadFile(request.Root(), relative)
			if err != nil {
				diagnose(core.DiagnosticTarget, core.DiagnosticWarning, "vulnerability-db.read", relative, err)
				return nil
			}
			found, unpinned, err := parse(relative, data)
			if err != nil {
				diagnose(core.DiagnosticTarget, core.DiagnosticWarning, "vulnerability-db.parse", relative, err)
				return nil
			}
			if unpinned > 0 {
				diagnose(core.DiagnosticTarget, core.DiagnosticInfo, "vulnerability-db.unpinned", relative,
					fmt.Errorf("%d dependencies without an exact version were not checked for known vulnerabilities; pin them or commit a lockfile", unpinned))
			}
			deps = append(deps, found...)
			return nil
		})
		if err != nil {
			diagnose(core.DiagnosticTarget, core.DiagnosticWarning, "vulnerability-db.target", "", err)
		}
	}
	return deps
}

// mergeAliases collapses advisories that alias each other (for example GHSA and PYSEC
// records for one CVE) and keeps the record with the most curated severity data.
func mergeAliases(ids []string, vulns map[string]osvVuln) []osvVuln {
	parent := map[string]string{}
	var find func(string) string
	find = func(id string) string {
		if parent[id] == "" || parent[id] == id {
			parent[id] = id
			return id
		}
		parent[id] = find(parent[id])
		return parent[id]
	}
	union := func(a, b string) {
		if rootA, rootB := find(a), find(b); rootA != rootB {
			parent[rootB] = rootA
		}
	}
	records := make([]osvVuln, len(ids))
	for i, id := range ids {
		record, ok := vulns[id]
		if !ok {
			record = osvVuln{ID: id}
		}
		records[i] = record
		find(id)
		for _, alias := range record.Aliases {
			union(id, alias)
		}
	}
	best := map[string]osvVuln{}
	var order []string
	for _, record := range records {
		root := find(record.ID)
		current, ok := best[root]
		if !ok {
			order = append(order, root)
		}
		if !ok || recordRank(record) > recordRank(current) {
			best[root] = record
		}
	}
	merged := make([]osvVuln, len(order))
	for i, root := range order {
		merged[i] = best[root]
	}
	return merged
}

func recordRank(vuln osvVuln) int {
	rank := 0
	if vuln.DatabaseSpecific.Severity != "" {
		rank += 4
	}
	if len(vuln.Severity) > 0 {
		rank += 2
	}
	if strings.HasPrefix(vuln.ID, "GHSA-") {
		rank++
	}
	return rank
}

func hasCVE(vulns map[string]osvVuln) bool {
	for _, vuln := range vulns {
		if len(cveIDs(vuln)) > 0 {
			return true
		}
	}
	return false
}

func cveIDs(vuln osvVuln) []string {
	var ids []string
	for _, id := range append([]string{vuln.ID}, vuln.Aliases...) {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			ids = append(ids, strings.ToUpper(id))
		}
	}
	return ids
}

func buildFinding(source string, dep Dependency, vuln osvVuln, kev map[string]kevEntry) (core.Finding, error) {
	label := vuln.ID
	if cves := cveIDs(vuln); len(cves) > 0 {
		label = cves[0]
	}
	pkg := fmt.Sprintf("%s@%s", dep.Name, dep.Version)
	summary := strings.TrimSpace(vuln.Summary)
	if summary == "" {
		summary = firstLine(vuln.Details)
	}
	if summary == "" {
		summary = "published vulnerability advisory (details unavailable)"
	}

	rule, category := ruleVulnerable, "vulnerable-dependency"
	severity := advisorySeverity(vuln)
	confidence := core.ConfidenceHigh
	if vuln.Summary == "" && vuln.Details == "" && len(vuln.Affected) == 0 {
		confidence = core.ConfidenceMedium // detail fetch failed; only the ID match is known
	}
	evidence := []core.Evidence{{
		Kind: core.EvidenceDependency, Snippet: pkg,
		Description: fmt.Sprintf("OSV advisory %s%s matches this exact %s version.", vuln.ID, aliasText(vuln), dep.Ecosystem),
	}}

	var exploited *kevEntry
	for _, cve := range cveIDs(vuln) {
		if entry, ok := kev[cve]; ok {
			exploited = &entry
			break
		}
	}
	message := fmt.Sprintf("[%s] %s (%s): %s", label, pkg, dep.Ecosystem, summary)
	if exploited != nil {
		severity = core.SeverityCritical
		message = "[Known Exploited] " + message
		description := fmt.Sprintf("%s is listed in the CISA Known Exploited Vulnerabilities catalog (added %s, remediation due %s).",
			exploited.CVEID, exploited.DateAdded, exploited.DueDate)
		if strings.EqualFold(exploited.RansomwareUse, "Known") {
			description += " Known use in ransomware campaigns."
		}
		evidence = append(evidence, core.Evidence{Kind: core.EvidenceOther, Description: description})
	}
	if strings.HasPrefix(vuln.ID, "MAL-") {
		rule, category, severity = ruleMalicious, "malicious-package", core.SeverityCritical
		message = fmt.Sprintf("[Malicious Package] %s (%s): %s", pkg, dep.Ecosystem, summary)
	}

	remediation := fmt.Sprintf("No fixed version is published for %s; remove or replace it, or apply the mitigations in the advisory.", dep.Name)
	if rule == ruleMalicious {
		remediation = fmt.Sprintf("Remove %s immediately, rotate any credentials exposed to environments where it was installed, and audit for compromise.", pkg)
	} else if fixed := fixedVersions(vuln, dep); len(fixed) > 0 {
		remediation = fmt.Sprintf("Upgrade %s to a fixed version (%s) and regenerate the lockfile.", dep.Name, strings.Join(fixed, ", "))
	}

	cwe := ""
	if len(vuln.DatabaseSpecific.CWEIDs) > 0 {
		cwe = vuln.DatabaseSpecific.CWEIDs[0]
	}
	return core.NewFinding(core.FindingInput{
		Source: source, Rule: rule, Message: message, Severity: severity, Category: category,
		Confidence: confidence, Location: core.Location{Path: dep.Path, Line: dep.Line},
		Evidence: evidence, Remediation: remediation, CWE: cwe,
		HelpURI:   "https://osv.dev/vulnerability/" + vuln.ID,
		StableKey: strings.Join([]string{dep.Ecosystem, dep.Name, dep.Version, vuln.ID}, ":"),
	})
}

// advisorySeverity prefers the curated database label, then the CVSS v3 vector.
func advisorySeverity(vuln osvVuln) core.Severity {
	switch strings.ToUpper(vuln.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return core.SeverityCritical
	case "HIGH":
		return core.SeverityHigh
	case "MODERATE", "MEDIUM":
		return core.SeverityMedium
	case "LOW":
		return core.SeverityLow
	}
	for _, entry := range vuln.Severity {
		if entry.Type != "CVSS_V3" {
			continue
		}
		if score, ok := cvss3BaseScore(entry.Score); ok {
			switch {
			case score >= 9.0:
				return core.SeverityCritical
			case score >= 7.0:
				return core.SeverityHigh
			case score >= 4.0:
				return core.SeverityMedium
			case score > 0:
				return core.SeverityLow
			default:
				return core.SeverityInfo
			}
		}
	}
	return core.SeverityMedium // unscored advisories still affect this exact version
}

// fixedVersions returns the fix for the range containing the installed version, or every
// published fix when the containing range cannot be determined.
func fixedVersions(vuln osvVuln, dep Dependency) []string {
	seen := map[string]bool{}
	var all, containing []string
	for _, affected := range vuln.Affected {
		if !strings.EqualFold(affected.Package.Ecosystem, dep.Ecosystem) ||
			normalizeName(dep.Ecosystem, affected.Package.Name) != normalizeName(dep.Ecosystem, dep.Name) {
			continue
		}
		for _, r := range affected.Ranges {
			if r.Type == "GIT" {
				continue // commit hashes are not installable versions
			}
			introduced := "0"
			for _, event := range r.Events {
				if version := event["introduced"]; version != "" {
					introduced = version
				}
				version := event["fixed"]
				if version == "" {
					continue
				}
				if !seen[version] {
					seen[version] = true
					all = append(all, version)
				}
				if compareVersions(dep.Version, introduced) >= 0 && compareVersions(dep.Version, version) < 0 {
					containing = append(containing, version)
				}
			}
		}
	}
	if len(containing) == 1 {
		return containing
	}
	return all
}

// compareVersions orders dotted versions by numeric and alphabetic segments. It is a
// heuristic for choosing a fix to display; advisory matching itself is done by OSV.
func compareVersions(a, b string) int {
	left, right := versionSegments(a), versionSegments(b)
	for i := 0; i < max(len(left), len(right)); i++ {
		// A trailing pre-release tag sorts before the release: 1.0.0rc1 < 1.0.0 < 1.0.0.post1.
		if i >= len(left) {
			if preRelease(right[i]) {
				return 1
			}
			return -1
		}
		if i >= len(right) {
			if preRelease(left[i]) {
				return -1
			}
			return 1
		}
		x, y := left[i], right[i]
		xNumeric, yNumeric := x != "" && strings.Trim(x, "0123456789") == "", y != "" && strings.Trim(y, "0123456789") == ""
		switch {
		case xNumeric && yNumeric:
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				return cmpInt(len(x), len(y))
			}
			if x != y {
				return strings.Compare(x, y)
			}
		case xNumeric != yNumeric:
			if xNumeric {
				return 1 // 1.0.1 > 1.0.rc1
			}
			return -1
		case x != y:
			return strings.Compare(x, y)
		}
	}
	return 0
}

func preRelease(segment string) bool {
	if segment == "" || strings.Trim(segment, "0123456789") == "" {
		return false
	}
	switch strings.ToLower(segment) {
	case "post", "rev", "r", "p":
		return false
	}
	return true
}

func versionSegments(version string) []string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	var segments []string
	var current strings.Builder
	digit := false
	flush := func() {
		if current.Len() > 0 {
			segments = append(segments, current.String())
			current.Reset()
		}
	}
	for _, char := range version {
		isDigit := char >= '0' && char <= '9'
		isAlpha := (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
		if !isDigit && !isAlpha {
			flush()
			continue
		}
		if current.Len() > 0 && isDigit != digit {
			flush()
		}
		digit = isDigit
		current.WriteRune(char)
	}
	flush()
	return segments
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	return 1
}

// normalizeName applies PEP 503 normalization for PyPI; other ecosystems compare exactly.
func normalizeName(ecosystem, name string) string {
	if ecosystem != EcosystemPyPI {
		return name
	}
	return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(name))
}

func aliasText(vuln osvVuln) string {
	if len(vuln.Aliases) == 0 {
		return ""
	}
	return " (" + strings.Join(vuln.Aliases, ", ") + ")"
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	if len(line) > 200 {
		line = line[:200] + "…"
	}
	return line
}

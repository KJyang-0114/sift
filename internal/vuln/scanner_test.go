package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

type fakeFeeds struct {
	advisories map[string][]string // "ecosystem/name@version" -> IDs
	vulns      map[string]osvVuln
	kev        []kevEntry
	osvStatus  int
	kevStatus  int
	pageToken  string // when set, the first page omits the last ID of every query
	calls      atomic.Int32
}

func (f *fakeFeeds) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		switch {
		case r.URL.Path == "/v1/querybatch":
			if f.osvStatus != 0 {
				w.WriteHeader(f.osvStatus)
				return
			}
			var body struct {
				Queries []struct {
					Package   struct{ Name, Ecosystem string } `json:"package"`
					Version   string                           `json:"version"`
					PageToken string                           `json:"page_token"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode querybatch: %v", err)
			}
			type vulnRef struct {
				ID string `json:"id"`
			}
			type queryResult struct {
				Vulns         []vulnRef `json:"vulns,omitempty"`
				NextPageToken string    `json:"next_page_token,omitempty"`
			}
			results := make([]queryResult, len(body.Queries))
			for i, query := range body.Queries {
				ids := f.advisories[query.Package.Ecosystem+"/"+query.Package.Name+"@"+query.Version]
				if f.pageToken != "" && len(ids) > 1 {
					if query.PageToken == "" {
						ids = ids[:len(ids)-1]
						results[i].NextPageToken = f.pageToken
					} else {
						ids = ids[len(ids)-1:]
					}
				}
				for _, id := range ids {
					results[i].Vulns = append(results[i].Vulns, vulnRef{ID: id})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			vuln, ok := f.vulns[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(vuln)
		case r.URL.Path == "/kev.json":
			if f.kevStatus != 0 {
				w.WriteHeader(f.kevStatus)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": f.kev})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func (f *fakeFeeds) scanner(t *testing.T) *Scanner {
	server := f.server(t)
	scanner := newScanner(server.Client(), server.URL, server.URL+"/kev.json")
	scanner.feeds.retryDelay = 0
	return scanner
}

func writeFiles(t *testing.T, files map[string]string) core.ScanRequest {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	request, err := core.NewScanRequest(root, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func lodashAdvisory() osvVuln {
	vuln := osvVuln{ID: "GHSA-p6mc-m468-83gw", Summary: "Prototype Pollution in lodash", Aliases: []string{"CVE-2020-8203"}}
	vuln.DatabaseSpecific.Severity = "HIGH"
	vuln.DatabaseSpecific.CWEIDs = []string{"CWE-1321"}
	vuln.Affected = append(vuln.Affected, affectedRange(EcosystemNPM, "lodash", "SEMVER", "3.7.0", "4.17.19"))
	return vuln
}

func affectedRange(ecosystem, name, kind, introduced, fixed string) (affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
}) {
	affected.Package.Name, affected.Package.Ecosystem = name, ecosystem
	affected.Ranges = append(affected.Ranges, struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	}{Type: kind, Events: []map[string]string{{"introduced": introduced}, {"fixed": fixed}}})
	return affected
}

func TestScannerReportsAdvisoriesAndPrioritizesKnownExploited(t *testing.T) {
	django := osvVuln{ID: "GHSA-2gwj-7jmv-h26r", Summary: "SQL Injection in Django", Aliases: []string{"CVE-2022-28346", "PYSEC-2022-190"}}
	django.DatabaseSpecific.Severity = "CRITICAL"
	django.Affected = append(django.Affected,
		affectedRange(EcosystemPyPI, "django", "ECOSYSTEM", "2.2", "2.2.28"),
		affectedRange(EcosystemPyPI, "django", "ECOSYSTEM", "3.2", "3.2.13"))
	pysec := osvVuln{ID: "PYSEC-2022-190", Details: "Duplicate record without severity.", Aliases: []string{"CVE-2022-28346", "GHSA-2gwj-7jmv-h26r"}}

	feeds := &fakeFeeds{
		advisories: map[string][]string{
			"npm/lodash@4.17.15":         {"GHSA-p6mc-m468-83gw"},
			"PyPI/Django@3.2.0":          {"PYSEC-2022-190", "GHSA-2gwj-7jmv-h26r"},
			"Go/example.com/safe@v1.0.0": nil,
		},
		vulns: map[string]osvVuln{"GHSA-p6mc-m468-83gw": lodashAdvisory(), "GHSA-2gwj-7jmv-h26r": django, "PYSEC-2022-190": pysec},
		kev:   []kevEntry{{CVEID: "CVE-2020-8203", DateAdded: "2026-01-02", DueDate: "2026-01-23", RansomwareUse: "Known"}},
	}
	request := writeFiles(t, map[string]string{
		"web/package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "web"},
    "node_modules/lodash": {"version": "4.17.15"}
  }
}`,
		"api/requirements.txt": "requests>=2\nDjango==3.2.0\n",
		"svc/go.mod":           "module example.com/svc\n\nrequire example.com/safe v1.0.0\n",
		"web/node_modules/evil/package-lock.json": `{"packages": {"node_modules/x": {"version": "1.0.0"}}}`,
	})

	result := feeds.scanner(t).Analyze(context.Background(), request)

	if len(result.Findings) != 2 {
		t.Fatalf("findings=%d want 2 (aliases merged): %+v", len(result.Findings), result.Findings)
	}
	byPath := map[string]core.Finding{}
	for _, finding := range result.Findings {
		byPath[finding.Location.Path] = finding
	}
	lodash := byPath["web/package-lock.json"]
	if lodash.Severity != core.SeverityCritical || !strings.HasPrefix(lodash.Message, "[Known Exploited] [CVE-2020-8203] lodash@4.17.15") {
		t.Fatalf("KEV finding not prioritized: %s %s", lodash.Severity, lodash.Message)
	}
	if lodash.Location.Line != 5 || lodash.CWE != "CWE-1321" || lodash.HelpURI != "https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw" {
		t.Fatalf("lodash metadata: %+v", lodash)
	}
	if len(lodash.Evidence) != 2 || !strings.Contains(lodash.Evidence[1].Description, "ransomware") {
		t.Fatalf("KEV evidence missing: %+v", lodash.Evidence)
	}
	if !strings.Contains(lodash.Remediation, "(4.17.19)") {
		t.Fatalf("remediation=%q", lodash.Remediation)
	}

	djangoFinding := byPath["api/requirements.txt"]
	if djangoFinding.Severity != core.SeverityCritical || djangoFinding.Location.Line != 2 ||
		!strings.Contains(djangoFinding.Message, "SQL Injection in Django") || !strings.Contains(djangoFinding.Remediation, "(3.2.13)") {
		t.Fatalf("django finding: %+v", djangoFinding)
	}
	if djangoFinding.Rule != ruleVulnerable || djangoFinding.Category != "vulnerable-dependency" || djangoFinding.Confidence != core.ConfidenceHigh {
		t.Fatalf("django classification: %+v", djangoFinding)
	}

	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "vulnerability-db.unpinned" ||
		result.Diagnostics[0].Severity != core.DiagnosticInfo || result.Diagnostics[0].Path != "api/requirements.txt" {
		t.Fatalf("diagnostics=%+v", result.Diagnostics)
	}
	if result.HasErrors() {
		t.Fatal("complete scan reported errors")
	}
}

func TestScannerMakesNoRequestsWithoutLockfiles(t *testing.T) {
	feeds := &fakeFeeds{}
	request := writeFiles(t, map[string]string{"app.py": "print('hi')\n", "package.json": `{"dependencies": {"lodash": "^4"}}`})
	result := feeds.scanner(t).Analyze(context.Background(), request)
	if feeds.calls.Load() != 0 || len(result.Findings) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("calls=%d result=%+v", feeds.calls.Load(), result)
	}
}

func TestScannerSkipsKEVWhenNoAdvisoryHasCVE(t *testing.T) {
	feeds := &fakeFeeds{
		advisories: map[string][]string{"npm/lodash@4.17.15": {"GHSA-only"}},
		vulns:      map[string]osvVuln{"GHSA-only": {ID: "GHSA-only", Summary: "No CVE assigned"}},
		kevStatus:  http.StatusInternalServerError,
	}
	request := writeFiles(t, map[string]string{"package-lock.json": `{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}`})
	result := feeds.scanner(t).Analyze(context.Background(), request)
	if len(result.Findings) != 1 || len(result.Diagnostics) != 0 || result.Findings[0].Severity != core.SeverityMedium {
		t.Fatalf("result=%+v", result)
	}
}

func TestScannerOSVFailureIsPartialNotClean(t *testing.T) {
	feeds := &fakeFeeds{osvStatus: http.StatusServiceUnavailable}
	request := writeFiles(t, map[string]string{"package-lock.json": `{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}`})
	result := feeds.scanner(t).Analyze(context.Background(), request)
	if len(result.Findings) != 0 || !result.HasErrors() || result.Diagnostics[0].Code != "osv.unavailable" {
		t.Fatalf("result=%+v", result)
	}
	if got := feeds.calls.Load(); got != 3 {
		t.Fatalf("requests=%d want 3 (two retries)", got)
	}
}

func TestScannerKEVFailureKeepsFindingsWithWarning(t *testing.T) {
	feeds := &fakeFeeds{
		advisories: map[string][]string{"npm/lodash@4.17.15": {"GHSA-p6mc-m468-83gw"}},
		vulns:      map[string]osvVuln{"GHSA-p6mc-m468-83gw": lodashAdvisory()},
		kevStatus:  http.StatusForbidden,
	}
	request := writeFiles(t, map[string]string{"package-lock.json": `{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}`})
	result := feeds.scanner(t).Analyze(context.Background(), request)
	if len(result.Findings) != 1 || result.Findings[0].Severity != core.SeverityHigh || result.HasErrors() {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "kev.unavailable" || result.Diagnostics[0].Severity != core.DiagnosticWarning {
		t.Fatalf("diagnostics=%+v", result.Diagnostics)
	}
}

func TestScannerDetailFailureKeepsMatchAsPartial(t *testing.T) {
	feeds := &fakeFeeds{advisories: map[string][]string{"npm/lodash@4.17.15": {"GHSA-missing"}}}
	request := writeFiles(t, map[string]string{"package-lock.json": `{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}`})
	result := feeds.scanner(t).Analyze(context.Background(), request)
	if len(result.Findings) != 1 || result.Findings[0].Confidence != core.ConfidenceMedium || !result.HasErrors() {
		t.Fatalf("result=%+v", result)
	}
}

func TestScannerReportsMaliciousPackagesAndSkipsWithdrawn(t *testing.T) {
	feeds := &fakeFeeds{
		advisories: map[string][]string{"npm/evil-pkg@1.0.0": {"MAL-2026-1", "GHSA-withdrawn"}},
		vulns: map[string]osvVuln{
			"MAL-2026-1":     {ID: "MAL-2026-1", Summary: "Malicious code in evil-pkg (npm)"},
			"GHSA-withdrawn": {ID: "GHSA-withdrawn", Summary: "Retracted", Withdrawn: "2026-01-01T00:00:00Z"},
		},
	}
	request := writeFiles(t, map[string]string{"package-lock.json": `{"packages": {"node_modules/evil-pkg": {"version": "1.0.0"}}}`})
	result := feeds.scanner(t).Analyze(context.Background(), request)
	if len(result.Findings) != 1 {
		t.Fatalf("findings=%+v", result.Findings)
	}
	finding := result.Findings[0]
	if finding.Rule != ruleMalicious || finding.Severity != core.SeverityCritical || finding.Category != "malicious-package" ||
		!strings.HasPrefix(finding.Message, "[Malicious Package] evil-pkg@1.0.0") || !strings.Contains(finding.Remediation, "rotate") {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestScannerFollowsOSVPagination(t *testing.T) {
	second := lodashAdvisory()
	second.ID, second.Aliases = "GHSA-second", []string{"CVE-2021-23337"}
	feeds := &fakeFeeds{
		advisories: map[string][]string{"npm/lodash@4.17.15": {"GHSA-p6mc-m468-83gw", "GHSA-second"}},
		vulns:      map[string]osvVuln{"GHSA-p6mc-m468-83gw": lodashAdvisory(), "GHSA-second": second},
		pageToken:  "page-2",
	}
	request := writeFiles(t, map[string]string{"package-lock.json": `{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}`})
	result := feeds.scanner(t).Analyze(context.Background(), request)
	if len(result.Findings) != 2 {
		t.Fatalf("findings=%d want 2 across pages", len(result.Findings))
	}
}

func TestScannerHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, r.Context().Err()
	})}
	scanner := newScanner(client, "http://osv.invalid", "http://kev.invalid")
	request := writeFiles(t, map[string]string{"package-lock.json": `{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}`})
	result := scanner.Analyze(ctx, request)
	if !result.HasErrors() || !errors.Is(result.Diagnostics[0].Cause, context.Canceled) {
		t.Fatalf("result=%+v", result)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func TestDoJSONRejectsOversizedResponses(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"x":"` + strings.Repeat("a", 64) + `"}`)), Request: r}, nil
	})}
	feeds := feedClient{http: client}
	var out map[string]string
	if err := feeds.doJSON(context.Background(), http.MethodGet, "http://example.invalid", nil, 16, &out); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}

func TestFixedVersionsSelectsContainingRange(t *testing.T) {
	vuln := osvVuln{}
	vuln.Affected = append(vuln.Affected,
		affectedRange(EcosystemPyPI, "Django", "ECOSYSTEM", "2.2", "2.2.28"),
		affectedRange(EcosystemPyPI, "django", "ECOSYSTEM", "3.2", "3.2.13"),
		affectedRange(EcosystemPyPI, "django", "GIT", "0", "abc123"),
		affectedRange(EcosystemPyPI, "other", "ECOSYSTEM", "0", "9.9"))
	got := fixedVersions(vuln, Dependency{Ecosystem: EcosystemPyPI, Name: "Django", Version: "3.2.0"})
	if !reflect.DeepEqual(got, []string{"3.2.13"}) {
		t.Fatalf("fixed=%v", got)
	}
	got = fixedVersions(vuln, Dependency{Ecosystem: EcosystemPyPI, Name: "django", Version: "9.0"})
	if !reflect.DeepEqual(got, []string{"2.2.28", "3.2.13"}) {
		t.Fatalf("fallback fixed=%v", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.10", "1.2.9", 1},
		{"v0.17.0", "0.23.0", -1},
		{"4.17.15", "4.17.15", 0},
		{"1.0.0rc1", "1.0.0", -1},
		{"1.0.1", "1.0.rc1", 1},
		{"0", "3.7.0", -1},
		{"1.0.0.post1", "1.0.0", 1},
		{"2.0.0-beta.2", "2.0.0", -1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCVSS3BaseScore(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H": 7.4,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vector, want := range cases {
		if got, ok := cvss3BaseScore(vector); !ok || got != want {
			t.Errorf("%s = %v,%v want %v", vector, got, ok, want)
		}
	}
	for _, invalid := range []string{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:X/AC:L", ""} {
		if _, ok := cvss3BaseScore(invalid); ok {
			t.Errorf("%q accepted", invalid)
		}
	}
}

func TestAdvisorySeverityFallsBackToCVSSThenMedium(t *testing.T) {
	vuln := osvVuln{}
	vuln.Severity = append(vuln.Severity, struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{"CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
	if got := advisorySeverity(vuln); got != core.SeverityCritical {
		t.Fatalf("cvss severity=%s", got)
	}
	vuln.DatabaseSpecific.Severity = "MODERATE"
	if got := advisorySeverity(vuln); got != core.SeverityMedium {
		t.Fatalf("database severity=%s", got)
	}
	if got := advisorySeverity(osvVuln{}); got != core.SeverityMedium {
		t.Fatalf("unscored severity=%s", got)
	}
}

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

// PackageVerifier verifies whether dependency packages actually exist.
type PackageVerifier struct {
	client     *http.Client
	retryDelay time.Duration
}

var _ core.Analyzer = (*PackageVerifier)(nil)

// NewPackageVerifier creates a new package verifier.
func NewPackageVerifier() *PackageVerifier {
	return newPackageVerifier(&http.Client{Timeout: 10 * time.Second})
}

func newPackageVerifier(client *http.Client) *PackageVerifier {
	return &PackageVerifier{client: client, retryDelay: 200 * time.Millisecond}
}

// Name returns the analyzer name.
func (pv *PackageVerifier) Name() string {
	return "package-verifier"
}

// DepFile describes a dependency file.
type DepFile struct {
	Path      string   `json:"path"`
	Ecosystem string   `json:"ecosystem"` // npm, pypi, cargo, go
	Packages  []string `json:"packages"`
}

// Analyze scans dependency files and verifies that referenced packages exist.
func (pv *PackageVerifier) Analyze(ctx context.Context, request core.ScanRequest) core.AnalysisResult {
	result := core.AnalysisResult{Findings: []core.Finding{}, Diagnostics: []core.Diagnostic{}}

	for _, target := range request.AbsoluteTargets() {
		if err := ctx.Err(); err != nil {
			result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
				Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
				Code: "package-verifier.cancelled", Source: pv.Name(), Message: err.Error(), Cause: err,
			})
			return result
		}
		depFiles, err := pv.findDepFiles(target)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
				Kind: core.DiagnosticTarget, Severity: core.DiagnosticWarning,
				Code: "package-verifier.target", Source: pv.Name(), Message: err.Error(), Cause: err,
			})
			continue
		}
		for _, df := range depFiles {
			for _, pkg := range df.Packages {
				state, err := pv.verifyPackage(ctx, df.Ecosystem, pkg)
				if err != nil {
					result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
						Kind: core.DiagnosticIntegration, Severity: core.DiagnosticError,
						Code: "registry.unavailable", Source: pv.Name(),
						Message: fmt.Sprintf("Unable to verify %s package %q: %v", df.Ecosystem, pkg, err), Cause: err,
					})
					continue
				}
				if state == packageMissing {
					relativePath, pathErr := request.RelativePath(df.Path)
					if pathErr != nil {
						result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
							Kind: core.DiagnosticTarget, Severity: core.DiagnosticError,
							Code: "package-verifier.location.outside-root", Source: pv.Name(),
							Message: "Dependency file is outside the scan root", Cause: pathErr,
						})
						continue
					}
					finding, findingErr := core.NewFinding(core.FindingInput{
						Source: pv.Name(), Rule: "sift.hallucinated-package",
						Message:  fmt.Sprintf("[Missing Public Package] %q was not found in the public %s registry. Verify the dependency name and intended registry; it may be private or misspelled.", pkg, df.Ecosystem),
						Severity: core.SeverityMedium, Category: "supply-chain", Confidence: core.ConfidenceHigh,
						Location: core.Location{Path: relativePath},
						Evidence: []core.Evidence{{
							Kind: core.EvidenceDependency, Snippet: pkg,
							Description: fmt.Sprintf("The %s registry returned a confirmed not-found response.", df.Ecosystem),
						}},
						Remediation: "Verify the dependency name and replace it with a trusted package that exists in the configured registry.",
						StableKey:   df.Ecosystem + ":" + pkg,
					})
					if findingErr != nil {
						result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
							Kind: core.DiagnosticAnalyzer, Severity: core.DiagnosticError,
							Code: "package-verifier.invalid-finding", Source: pv.Name(),
							Message: findingErr.Error(), Cause: findingErr,
						})
						continue
					}
					result.Findings = append(result.Findings, finding)
				}
			}
		}
	}

	return result
}

// findDepFiles locates dependency files in the target directory.
func (pv *PackageVerifier) findDepFiles(target string) ([]DepFile, error) {
	var depFiles []DepFile

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip common excluded directories
		skipDirs := []string{"node_modules", "vendor", ".git", "__pycache__", "dist", "target", "venv", ".venv", "site-packages"}
		if info.IsDir() {
			for _, d := range skipDirs {
				if info.Name() == d {
					return filepath.SkipDir
				}
			}
			return nil
		}

		base := filepath.Base(path)
		switch base {
		case "package.json":
			pkgs := parsePackageJSON(path)
			if len(pkgs) > 0 {
				depFiles = append(depFiles, DepFile{Path: path, Ecosystem: "npm", Packages: pkgs})
			}

		case "requirements.txt":
			pkgs := parseRequirementsTxt(path)
			if len(pkgs) > 0 {
				depFiles = append(depFiles, DepFile{Path: path, Ecosystem: "pypi", Packages: pkgs})
			}

		case "Pipfile":
			// Pipfile uses TOML format, simplified parsing
			pkgs := parsePipfile(path)
			if len(pkgs) > 0 {
				depFiles = append(depFiles, DepFile{Path: path, Ecosystem: "pypi", Packages: pkgs})
			}

		case "Cargo.toml":
			pkgs := parseCargoToml(path)
			if len(pkgs) > 0 {
				depFiles = append(depFiles, DepFile{Path: path, Ecosystem: "cargo", Packages: pkgs})
			}

		case "go.mod":
			pkgs := parseGoMod(path)
			if len(pkgs) > 0 {
				depFiles = append(depFiles, DepFile{Path: path, Ecosystem: "go", Packages: pkgs})
			}
		}
		return nil
	})

	return depFiles, err
}

// packageState separates a confirmed response from an unavailable registry.
type packageState int

const (
	packageUnknown packageState = iota
	packageExists
	packageMissing
)

// verifyPackage queries the public registry. Unknown results never become findings.
func (pv *PackageVerifier) verifyPackage(ctx context.Context, ecosystem, name string) (packageState, error) {
	switch ecosystem {
	case "npm":
		return pv.checkNPM(ctx, name)
	case "pypi":
		return pv.checkPyPI(ctx, name)
	case "cargo":
		return pv.checkCargo(ctx, name)
	case "go":
		return pv.checkGoProxy(ctx, name)
	default:
		return packageUnknown, fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
}

func (pv *PackageVerifier) checkNPM(ctx context.Context, name string) (packageState, error) {
	state, err := pv.checkStatus(ctx, "https://registry.npmjs.org/"+strings.TrimSpace(name))
	if state == packageMissing && strings.HasPrefix(name, "@") {
		return packageUnknown, fmt.Errorf("scoped package is not visible in the public npm registry; private packages require their configured registry")
	}
	return state, err
}

func (pv *PackageVerifier) checkPyPI(ctx context.Context, name string) (packageState, error) {
	return pv.checkStatus(ctx, "https://pypi.org/pypi/"+strings.TrimSpace(name)+"/json")
}

func (pv *PackageVerifier) checkGoProxy(ctx context.Context, name string) (packageState, error) {
	// Go proxies escape uppercase ASCII letters as ! followed by lowercase.
	// https://go.dev/ref/mod#goproxy-protocol
	var escaped strings.Builder
	for _, char := range strings.TrimSpace(name) {
		if char >= 'A' && char <= 'Z' {
			escaped.WriteRune('!')
			char += 'a' - 'A'
		}
		escaped.WriteRune(char)
	}
	state, err := pv.checkStatus(ctx, "https://proxy.golang.org/"+escaped.String()+"/@latest")
	if state == packageMissing {
		return packageUnknown, fmt.Errorf("module is not visible in the public Go proxy; it may be private or excluded from the proxy")
	}
	return state, err
}

func (pv *PackageVerifier) checkStatus(ctx context.Context, url string) (packageState, error) {
	response, err := pv.do(ctx, http.MethodHead, url)
	if err != nil {
		return packageUnknown, err
	}
	defer response.Body.Close()
	return registryStatus(response.StatusCode)
}

func registryStatus(status int) (packageState, error) {
	switch status {
	case http.StatusOK:
		return packageExists, nil
	case http.StatusNotFound:
		return packageMissing, nil
	default:
		return packageUnknown, fmt.Errorf("registry returned HTTP %d (%s)", status, http.StatusText(status))
	}
}

func (pv *PackageVerifier) checkCargo(ctx context.Context, name string) (packageState, error) {
	response, err := pv.do(ctx, http.MethodGet, "https://crates.io/api/v1/crates/"+strings.TrimSpace(name))
	if err != nil {
		return packageUnknown, err
	}
	defer response.Body.Close()
	state, err := registryStatus(response.StatusCode)
	if err != nil || state != packageExists {
		return state, err
	}
	const maxBody = 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return packageUnknown, fmt.Errorf("read registry response: %w", err)
	}
	if len(body) > maxBody {
		return packageUnknown, fmt.Errorf("registry response exceeds %d bytes", maxBody)
	}
	var result struct {
		Crate struct {
			Name string `json:"name"`
		} `json:"crate"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return packageUnknown, fmt.Errorf("invalid registry response: %w", err)
	}
	if result.Crate.Name != name {
		return packageUnknown, fmt.Errorf("registry response does not identify the requested crate")
	}
	return packageExists, nil
}

// do retries transient failures at most twice. Long Retry-After values are not
// shortened: the caller receives an unknown result instead of hammering a registry.
func (pv *PackageVerifier) do(ctx context.Context, method, url string) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("User-Agent", "sift/0.2 (+https://github.com/KJyang-0114/sift)")
		response, err := pv.client.Do(request)
		if ctx.Err() != nil {
			if response != nil {
				response.Body.Close()
			}
			return nil, ctx.Err()
		}
		transient := err != nil
		if response != nil {
			switch response.StatusCode {
			case 429, 500, 502, 503, 504:
				transient = true
			}
		}
		if !transient || attempt == 2 {
			return response, err
		}
		delay := pv.retryDelay * time.Duration(1<<attempt)
		if response != nil {
			if retryAfter := response.Header.Get("Retry-After"); retryAfter != "" {
				if value, ok := retryAfterDelay(retryAfter, time.Now()); ok && value > delay {
					delay = value
				}
			}
			if delay > 2*time.Second {
				return response, err
			}
			response.Body.Close()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func retryAfterDelay(value string, now time.Time) (time.Duration, bool) {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		// Bound arithmetic before converting untrusted seconds to a duration.
		if seconds > 2 {
			return 3 * time.Second, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	if date, err := http.ParseTime(value); err == nil {
		delay := date.Sub(now)
		if delay < 0 {
			delay = 0
		}
		return delay, true
	}
	return 0, false
}

// ── Dependency File Parsers ──

func parsePackageJSON(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkg struct {
		Dependencies     map[string]string `json:"dependencies"`
		DevDependencies  map[string]string `json:"devDependencies"`
		PeerDependencies map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	var pkgs []string
	for name := range pkg.Dependencies {
		pkgs = append(pkgs, name)
	}
	for name := range pkg.DevDependencies {
		pkgs = append(pkgs, name)
	}
	for name := range pkg.PeerDependencies {
		pkgs = append(pkgs, name)
	}
	return pkgs
}

func parseRequirementsTxt(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkgs []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Extract package name (strip version specifiers)
		name := strings.SplitN(line, "==", 2)[0]
		name = strings.SplitN(name, ">=", 2)[0]
		name = strings.SplitN(name, "<=", 2)[0]
		name = strings.SplitN(name, "~=", 2)[0]
		name = strings.TrimSpace(name)
		if name != "" {
			pkgs = append(pkgs, name)
		}
	}
	return pkgs
}

func parsePipfile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkgs []string
	inPackages := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[packages]" {
			inPackages = true
			continue
		}
		if inPackages && strings.HasPrefix(trimmed, "[") {
			break
		}
		if inPackages && trimmed != "" {
			name := strings.SplitN(trimmed, "=", 2)[0]
			name = strings.Trim(name, ` "`)
			if name != "" {
				pkgs = append(pkgs, name)
			}
		}
	}
	return pkgs
}

func parseCargoToml(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkgs []string
	inDeps := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[dependencies]" || trimmed == "[dev-dependencies]" {
			inDeps = true
			continue
		}
		if inDeps && strings.HasPrefix(trimmed, "[") {
			inDeps = false
			continue
		}
		if inDeps && trimmed != "" {
			name := strings.SplitN(trimmed, "=", 2)[0]
			name = strings.Trim(name, ` "`)
			if name != "" {
				pkgs = append(pkgs, name)
			}
		}
	}
	return pkgs
}

func parseGoMod(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var packages []string
	inRequire := false
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "//", 2)[0])
		if len(fields) == 0 {
			continue
		}
		if inRequire && fields[0] == ")" {
			inRequire = false
			continue
		}
		if fields[0] == "require" {
			fields = fields[1:]
			if len(fields) == 1 && fields[0] == "(" {
				inRequire = true
				continue
			}
		} else if !inRequire {
			continue
		}
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if strings.HasPrefix(name, "\"") {
			unquoted, err := strconv.Unquote(name)
			if err != nil {
				continue
			}
			name = unquoted
		}
		if name != "" && !seen[name] {
			packages = append(packages, name)
			seen[name] = true
		}
	}
	return packages
}

// splitTargets splits a comma-separated target string into individual paths.
// Used to handle diff mode where targets are passed as a comma-separated list.
func splitTargets(target string) []string {
	if !strings.Contains(target, ",") {
		return []string{target}
	}
	var result []string
	for _, t := range strings.Split(target, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			result = append(result, t)
		}
	}
	if len(result) == 0 {
		return []string{target}
	}
	return result
}

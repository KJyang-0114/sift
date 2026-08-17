package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/core"
)

// PackageVerifier verifies whether dependency packages actually exist.
type PackageVerifier struct {
	client *http.Client
}

var _ core.Analyzer = (*PackageVerifier)(nil)

// NewPackageVerifier creates a new package verifier.
func NewPackageVerifier() *PackageVerifier {
	return newPackageVerifier(&http.Client{Timeout: 10 * time.Second})
}

func newPackageVerifier(client *http.Client) *PackageVerifier {
	return &PackageVerifier{client: client}
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
				exists, err := pv.verifyPackage(ctx, df.Ecosystem, pkg)
				if err != nil {
					result.Diagnostics = append(result.Diagnostics, core.Diagnostic{
						Kind: core.DiagnosticIntegration, Severity: core.DiagnosticWarning,
						Code: "registry.unavailable", Source: pv.Name(),
						Message: fmt.Sprintf("Unable to verify %s package %q: %v", df.Ecosystem, pkg, err), Cause: err,
					})
					continue
				}
				if !exists && !isCommonTypo(pkg) {
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
						Message:  fmt.Sprintf("[Hallucinated Package] %q does not exist in the %s registry. This may be an AI hallucination or typo-squatting attack.", pkg, df.Ecosystem),
						Severity: core.SeverityCritical, Category: "supply-chain", Confidence: core.ConfidenceHigh,
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

// verifyPackage queries the registry API to check whether a package exists.
func (pv *PackageVerifier) verifyPackage(ctx context.Context, ecosystem, name string) (bool, error) {
	switch ecosystem {
	case "npm":
		return pv.checkNPM(ctx, name)
	case "pypi":
		return pv.checkPyPI(ctx, name)
	case "cargo":
		return pv.checkCargo(ctx, name)
	case "go":
		// Go modules are harder to verify (private repos are common), use proxy check first
		return pv.checkGoProxy(ctx, name)
	}
	return true, nil
}

func (pv *PackageVerifier) checkNPM(ctx context.Context, name string) (bool, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", strings.TrimSpace(name))
	resp, err := pv.do(ctx, http.MethodHead, url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

func (pv *PackageVerifier) checkPyPI(ctx context.Context, name string) (bool, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", strings.TrimSpace(name))
	resp, err := pv.do(ctx, http.MethodHead, url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

func (pv *PackageVerifier) checkCargo(ctx context.Context, name string) (bool, error) {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s", strings.TrimSpace(name))
	resp, err := pv.do(ctx, http.MethodGet, url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return false, nil
	}

	var result struct {
		Crate struct {
			Name string `json:"name"`
		} `json:"crate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Crate.Name == name, nil
}

func (pv *PackageVerifier) checkGoProxy(ctx context.Context, name string) (bool, error) {
	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", strings.TrimSpace(name))
	resp, err := pv.do(ctx, http.MethodHead, url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

func (pv *PackageVerifier) do(ctx context.Context, method, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	return pv.client.Do(request)
}

// isCommonTypo checks whether the name is a common package typo (potential typo-squatting).
func isCommonTypo(name string) bool {
	// Allow common security package names to pass through (reduce false positives)
	commonPrefixes := []string{
		"@types/", "@babel/", "@eslint/", "@anthropic-ai/",
		"eslint-plugin-", "babel-plugin-",
	}
	for _, prefix := range commonPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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

	var pkgs []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "module ") {
			continue
		}
		// Extract require lines
		if strings.HasPrefix(trimmed, "require ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				name := parts[1]
				if strings.Count(name, ".") >= 1 {
					pkgs = append(pkgs, name)
				}
			}
		}
	}
	return pkgs
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

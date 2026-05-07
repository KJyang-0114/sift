package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJyang-0114/sift/internal/static"
)

// PackageVerifier verifies whether dependency packages actually exist.
type PackageVerifier struct {
	client *http.Client
}

// NewPackageVerifier creates a new package verifier.
func NewPackageVerifier() *PackageVerifier {
	return &PackageVerifier{
		client: &http.Client{Timeout: 10 * time.Second},
	}
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

// Analyze scans all dependency files in the target directory and verifies that packages exist.
func (pv *PackageVerifier) Analyze(target string) ([]static.Finding, error) {
	var allFindings []static.Finding

	depFiles, err := pv.findDepFiles(target)
	if err != nil {
		return nil, fmt.Errorf("failed to locate dependency files: %w", err)
	}

	for _, df := range depFiles {
		for _, pkg := range df.Packages {
			exists, err := pv.verifyPackage(df.Ecosystem, pkg)
			if err != nil {
				// Skip on network errors, do not block the scan
				continue
			}
			if !exists && !isCommonTypo(pkg) {
				allFindings = append(allFindings, static.Finding{
					ID:       "sift.hallucinated-package",
					Rule:     "sift.hallucinated-package",
					Message:  fmt.Sprintf("[Hallucinated Package] \"%s\" does not exist in the %s registry. This may be an AI hallucination or typo-squatting attack.", pkg, df.Ecosystem),
					Severity: static.SeverityCritical,
					Category: "security",
					File:     df.Path,
					Line:     0,
					Column:   0,
					Code:     pkg,
				})
			}
		}
	}

	return allFindings, nil
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
func (pv *PackageVerifier) verifyPackage(ecosystem, name string) (bool, error) {
	switch ecosystem {
	case "npm":
		return pv.checkNPM(name)
	case "pypi":
		return pv.checkPyPI(name)
	case "cargo":
		return pv.checkCargo(name)
	case "go":
		// Go modules are harder to verify (private repos are common), use proxy check first
		return pv.checkGoProxy(name)
	}
	return true, nil
}

func (pv *PackageVerifier) checkNPM(name string) (bool, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", strings.TrimSpace(name))
	resp, err := pv.client.Head(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

func (pv *PackageVerifier) checkPyPI(name string) (bool, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", strings.TrimSpace(name))
	resp, err := pv.client.Head(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

func (pv *PackageVerifier) checkCargo(name string) (bool, error) {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s", strings.TrimSpace(name))
	resp, err := pv.client.Get(url)
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

func (pv *PackageVerifier) checkGoProxy(name string) (bool, error) {
	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", strings.TrimSpace(name))
	resp, err := pv.client.Head(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
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
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
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

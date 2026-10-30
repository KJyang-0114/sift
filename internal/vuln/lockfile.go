package vuln

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// OSV ecosystem identifiers. https://ossf.github.io/osv-schema/#affectedpackage-field
const (
	EcosystemNPM   = "npm"
	EcosystemPyPI  = "PyPI"
	EcosystemGo    = "Go"
	EcosystemCrate = "crates.io"
)

// Dependency is one exactly-versioned package resolved from a lockfile.
type Dependency struct {
	Ecosystem string
	Name      string
	Version   string
	Path      string // repository-relative lockfile path
	Line      int    // 1-based; 0 when the entry could not be located
}

func (d Dependency) key() string {
	return d.Ecosystem + "\x00" + d.Name + "\x00" + d.Version
}

// lockfileParser extracts dependencies; unpinned counts manifest entries without an exact version.
type lockfileParser func(relativePath string, data []byte) (deps []Dependency, unpinned int, err error)

// parserFor returns the parser for a lockfile base name, or nil when the file is not a lockfile.
func parserFor(base string) lockfileParser {
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		return parseNPMLock
	case base == "poetry.lock" || base == "uv.lock":
		return parsePythonTOMLLock
	case base == "Pipfile.lock":
		return parsePipfileLock
	case base == "Cargo.lock":
		return parseCargoLock
	case base == "go.mod":
		return parseGoMod
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return parseRequirements
	default:
		return nil
	}
}

func parseNPMLock(relativePath string, data []byte) ([]Dependency, int, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]npmV1Dependency `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", relativePath, err)
	}
	var deps []Dependency
	if len(lock.Packages) > 0 {
		for key, entry := range lock.Packages {
			index := strings.LastIndex(key, "node_modules/")
			if index < 0 || entry.Link {
				continue // root project or workspace link
			}
			name := entry.Name
			if name == "" {
				name = key[index+len("node_modules/"):]
			}
			if !registryVersion(entry.Version) {
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem: EcosystemNPM, Name: name, Version: entry.Version, Path: relativePath,
				Line: lineOf(data, fmt.Sprintf("%q:", key)),
			})
		}
	} else {
		var walk func(map[string]npmV1Dependency)
		walk = func(dependencies map[string]npmV1Dependency) {
			for name, entry := range dependencies {
				if registryVersion(entry.Version) {
					deps = append(deps, Dependency{
						Ecosystem: EcosystemNPM, Name: name, Version: entry.Version, Path: relativePath,
						Line: lineOf(data, fmt.Sprintf("%q:", name)),
					})
				}
				walk(entry.Dependencies)
			}
		}
		walk(lock.Dependencies)
	}
	return sortDependencies(deps), 0, nil
}

type npmV1Dependency struct {
	Version      string                     `json:"version"`
	Dependencies map[string]npmV1Dependency `json:"dependencies"`
}

// parsePythonTOMLLock reads poetry.lock and uv.lock [[package]] tables.
func parsePythonTOMLLock(relativePath string, data []byte) ([]Dependency, int, error) {
	var lock struct {
		Package []struct {
			Name    string         `toml:"name"`
			Version string         `toml:"version"`
			Source  map[string]any `toml:"source"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", relativePath, err)
	}
	var deps []Dependency
	for _, entry := range lock.Package {
		if entry.Name == "" || entry.Version == "" || localPythonSource(entry.Source) {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem: EcosystemPyPI, Name: entry.Name, Version: entry.Version, Path: relativePath,
			Line: lineOf(data, fmt.Sprintf("name = %q", entry.Name)),
		})
	}
	return sortDependencies(deps), 0, nil
}

// localPythonSource reports project or path sources that are not published packages.
func localPythonSource(source map[string]any) bool {
	for _, key := range []string{"editable", "virtual", "path", "directory"} {
		if _, ok := source[key]; ok {
			return true
		}
	}
	if kind, ok := source["type"].(string); ok {
		return kind == "directory" || kind == "file"
	}
	return false
}

func parsePipfileLock(relativePath string, data []byte) ([]Dependency, int, error) {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", relativePath, err)
	}
	var deps []Dependency
	unpinned := 0
	for _, section := range []string{"default", "develop"} {
		raw, ok := lock[section]
		if !ok {
			continue
		}
		var entries map[string]struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, 0, fmt.Errorf("parse %s [%s]: %w", relativePath, section, err)
		}
		for name, entry := range entries {
			version, ok := strings.CutPrefix(entry.Version, "==")
			if !ok || version == "" {
				unpinned++
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem: EcosystemPyPI, Name: name, Version: version, Path: relativePath,
				Line: lineOf(data, fmt.Sprintf("%q:", name)),
			})
		}
	}
	return sortDependencies(deps), unpinned, nil
}

func parseCargoLock(relativePath string, data []byte) ([]Dependency, int, error) {
	var lock struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
			Source  string `toml:"source"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", relativePath, err)
	}
	var deps []Dependency
	for _, entry := range lock.Package {
		// Workspace and path crates have no source and are not published to crates.io.
		if !strings.HasPrefix(entry.Source, "registry+") && !strings.HasPrefix(entry.Source, "sparse+") {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem: EcosystemCrate, Name: entry.Name, Version: entry.Version, Path: relativePath,
			Line: lineOf(data, fmt.Sprintf("name = %q", entry.Name)),
		})
	}
	return sortDependencies(deps), 0, nil
}

func parseGoMod(relativePath string, data []byte) ([]Dependency, int, error) {
	var deps []Dependency
	inRequire := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		fields := strings.Fields(strings.SplitN(scanner.Text(), "//", 2)[0])
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
		name := strings.Trim(fields[0], `"`)
		deps = append(deps, Dependency{
			Ecosystem: EcosystemGo, Name: name, Version: fields[1], Path: relativePath, Line: lineNumber,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", relativePath, err)
	}
	return deps, 0, nil
}

var requirementPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*$`)

// parseRequirements accepts only exact "name==version" pins; ranges cannot be matched to advisories.
func parseRequirements(relativePath string, data []byte) ([]Dependency, int, error) {
	var deps []Dependency
	unpinned := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSpace(strings.SplitN(line, " #", 2)[0])
		line = strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if fields := strings.Fields(line); len(fields) > 1 && strings.HasPrefix(fields[1], "--hash") {
			line = fields[0]
		}
		match := requirementPin.FindStringSubmatch(line)
		if match == nil {
			unpinned++
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem: EcosystemPyPI, Name: match[1], Version: match[2], Path: relativePath, Line: lineNumber,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", relativePath, err)
	}
	return deps, unpinned, nil
}

// registryVersion rejects git, file, alias and tarball specifiers that OSV cannot match.
func registryVersion(version string) bool {
	return version != "" && !strings.ContainsAny(version, ":/#@ ")
}

// lineOf returns the 1-based line of the first occurrence of needle, or 0.
func lineOf(data []byte, needle string) int {
	index := bytes.Index(data, []byte(needle))
	if index < 0 {
		return 0
	}
	return bytes.Count(data[:index], []byte("\n")) + 1
}

func sortDependencies(deps []Dependency) []Dependency {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps
}

package vuln

import (
	"reflect"
	"testing"
)

func summarize(deps []Dependency) []string {
	out := make([]string, len(deps))
	for i, dep := range deps {
		out[i] = dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
	}
	return out
}

func TestParseNPMLockV3SkipsRootLinksAndNonRegistryVersions(t *testing.T) {
	data := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/@scope/pkg": {"version": "2.0.0"},
    "node_modules/a/node_modules/b": {"version": "1.2.3"},
    "node_modules/aliased": {"name": "real-name", "version": "3.0.0"},
    "node_modules/workspace": {"resolved": "packages/workspace", "link": true},
    "node_modules/from-git": {"version": "git+https://github.com/x/y.git#abc"}
  }
}`)
	deps, unpinned, err := parseNPMLock("package-lock.json", data)
	if err != nil || unpinned != 0 {
		t.Fatalf("err=%v unpinned=%d", err, unpinned)
	}
	want := []string{"npm:@scope/pkg@2.0.0", "npm:b@1.2.3", "npm:real-name@3.0.0"}
	if got := summarize(deps); !reflect.DeepEqual(got, want) {
		t.Fatalf("deps=%v want %v", got, want)
	}
	if deps[0].Line != 5 {
		t.Fatalf("line=%d", deps[0].Line)
	}
}

func TestParseNPMLockV1WalksNestedDependencies(t *testing.T) {
	data := []byte(`{"lockfileVersion": 1, "dependencies": {
  "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
  "c": {"version": "file:../c"}
}}`)
	deps, _, err := parseNPMLock("package-lock.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := summarize(deps), []string{"npm:a@1.0.0", "npm:b@2.0.0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("deps=%v want %v", got, want)
	}
}

func TestParsePythonTOMLLocksSkipLocalSources(t *testing.T) {
	poetry := []byte(`[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "local-lib"
version = "0.1.0"
[package.source]
type = "directory"
url = "../local-lib"
`)
	uv := []byte(`version = 1
[[package]]
name = "myproject"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "pyyaml"
version = "5.3"
source = { registry = "https://pypi.org/simple" }
`)
	for name, tc := range map[string]struct {
		data []byte
		want []string
	}{
		"poetry.lock": {poetry, []string{"PyPI:requests@2.31.0"}},
		"uv.lock":     {uv, []string{"PyPI:pyyaml@5.3"}},
	} {
		deps, _, err := parsePythonTOMLLock(name, tc.data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := summarize(deps); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s deps=%v want %v", name, got, tc.want)
		}
	}
}

func TestParsePipfileLockCountsUnpinned(t *testing.T) {
	data := []byte(`{"_meta": {}, "default": {"django": {"version": "==3.2.0"}, "editable": {"path": "."}}, "develop": {"pytest": {"version": "==8.0.0"}}}`)
	deps, unpinned, err := parsePipfileLock("Pipfile.lock", data)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := summarize(deps), []string{"PyPI:django@3.2.0", "PyPI:pytest@8.0.0"}; !reflect.DeepEqual(got, want) || unpinned != 1 {
		t.Fatalf("deps=%v unpinned=%d", got, unpinned)
	}
}

func TestParseCargoLockSkipsWorkspaceCrates(t *testing.T) {
	data := []byte(`version = 3
[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "forked"
version = "0.2.0"
source = "git+https://github.com/x/forked#abc"
`)
	deps, _, err := parseCargoLock("Cargo.lock", data)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := summarize(deps), []string{"crates.io:serde@1.0.100"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("deps=%v want %v", got, want)
	}
}

func TestParseGoModRecordsLines(t *testing.T) {
	data := []byte("module example.com/app\n\ngo 1.25\n\nrequire golang.org/x/net v0.17.0\n\nrequire (\n\t\"example.com/quoted\" v1.0.0 // indirect\n)\nreplace example.com/x => ../x\n")
	deps, _, err := parseGoMod("go.mod", data)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := summarize(deps), []string{"Go:golang.org/x/net@v0.17.0", "Go:example.com/quoted@v1.0.0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("deps=%v want %v", got, want)
	}
	if deps[0].Line != 5 || deps[1].Line != 8 {
		t.Fatalf("lines=%d,%d", deps[0].Line, deps[1].Line)
	}
}

func TestParseRequirementsAcceptsOnlyExactPins(t *testing.T) {
	data := []byte(`# comment
Django==3.2.0
requests[socks] == 2.25.1 ; python_version >= "3.8"
pyyaml==5.3 --hash=sha256:abc \
flask>=2.0
-r other.txt
git+https://github.com/x/y.git
numpy===1.0
`)
	deps, unpinned, err := parseRequirements("requirements.txt", data)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PyPI:Django@3.2.0", "PyPI:requests@2.25.1", "PyPI:pyyaml@5.3"}
	if got := summarize(deps); !reflect.DeepEqual(got, want) || unpinned != 3 {
		t.Fatalf("deps=%v unpinned=%d", got, unpinned)
	}
	if deps[1].Line != 3 {
		t.Fatalf("line=%d", deps[1].Line)
	}
}

func TestParserForRecognizesLockfiles(t *testing.T) {
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "go.mod", "requirements.txt", "requirements-dev.txt"} {
		if parserFor(name) == nil {
			t.Errorf("%s not recognized", name)
		}
	}
	for _, name := range []string{"package.json", "Cargo.toml", "pyproject.toml", "requirements.in", "go.sum"} {
		if parserFor(name) != nil {
			t.Errorf("%s should not be parsed as a lockfile", name)
		}
	}
}

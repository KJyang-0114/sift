package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/KJyang-0114/sift/internal/core"
)

func finding(t *testing.T, rule, path string, line int, snippet string, severity core.Severity, confidence core.Confidence) core.Finding {
	t.Helper()
	f, err := core.NewFinding(core.FindingInput{
		Source: "semgrep", Rule: rule, Message: "issue in " + path, Severity: severity, Category: "security",
		Confidence: confidence, Location: core.Location{Path: path, Line: line},
		Evidence:    []core.Evidence{{Kind: core.EvidenceCode, Snippet: snippet}},
		Remediation: "fix it",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBaselineKeysIgnoreLineShiftsAndWhitespace(t *testing.T) {
	before := []core.Finding{finding(t, "sql", "app.py", 10, "db.execute(q + x)", core.SeverityHigh, core.ConfidenceHigh)}
	after := []core.Finding{finding(t, "sql", "app.py", 42, "  db.execute(q  +  x)", core.SeverityHigh, core.ConfidenceHigh)}
	if BaselineKeys(before)[0] != BaselineKeys(after)[0] {
		t.Fatal("key changed when only the line and indentation moved")
	}
	if before[0].Fingerprint == after[0].Fingerprint {
		t.Fatal("test precondition: finding fingerprints are line-based")
	}
	for name, other := range map[string]core.Finding{
		"rule":    finding(t, "xss", "app.py", 10, "db.execute(q + x)", core.SeverityHigh, core.ConfidenceHigh),
		"path":    finding(t, "sql", "other.py", 10, "db.execute(q + x)", core.SeverityHigh, core.ConfidenceHigh),
		"snippet": finding(t, "sql", "app.py", 10, "db.execute(q + y)", core.SeverityHigh, core.ConfidenceHigh),
	} {
		if BaselineKeys([]core.Finding{other})[0] == BaselineKeys(before)[0] {
			t.Errorf("%s change did not change the key", name)
		}
	}
}

func TestBaselineKeysDistinguishRepeatedLinesByOrder(t *testing.T) {
	first := finding(t, "sql", "app.py", 5, "run(x)", core.SeverityHigh, core.ConfidenceHigh)
	second := finding(t, "sql", "app.py", 9, "run(x)", core.SeverityHigh, core.ConfidenceHigh)
	keys := BaselineKeys([]core.Finding{second, first})
	if keys[0] == keys[1] {
		t.Fatal("identical snippets must get distinct keys")
	}
	if reordered := BaselineKeys([]core.Finding{first, second}); reordered[0] != keys[1] || reordered[1] != keys[0] {
		t.Fatal("keys depend on slice order instead of source order")
	}
}

func TestBaselineRoundTripAppliesSuppressionWithoutRemovingFindings(t *testing.T) {
	accepted := finding(t, "sql", "app.py", 10, "db.execute(q + x)", core.SeverityHigh, core.ConfidenceHigh)
	fixed := finding(t, "xss", "web.js", 3, "el.innerHTML = v", core.SeverityMedium, core.ConfidenceHigh)
	dir := t.TempDir()
	path := "baseline.json"
	baseline := NewBaseline([]core.Finding{accepted, fixed})
	baseline.Findings[0].Reason = "legacy admin tool, tracked in #12"
	if err := WriteBaseline(dir, path, baseline); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBaseline(dir, path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, baseline) {
		t.Fatalf("round trip changed baseline:\n%+v\n%+v", loaded, baseline)
	}

	moved := finding(t, "sql", "app.py", 30, "db.execute(q + x)", core.SeverityHigh, core.ConfidenceHigh)
	fresh := finding(t, "cmd", "run.sh", 1, "eval $x", core.SeverityCritical, core.ConfidenceHigh)
	input := []core.Finding{moved, fresh}
	updated, suppressed, stale := loaded.Apply(input, path)
	if suppressed != 1 || stale != 1 || len(updated) != 2 {
		t.Fatalf("suppressed=%d stale=%d len=%d", suppressed, stale, len(updated))
	}
	if !updated[0].Suppression.Suppressed || updated[0].Suppression.Reason != "baseline: legacy admin tool, tracked in #12" {
		t.Fatalf("suppression=%+v", updated[0].Suppression)
	}
	if updated[1].Suppression.Suppressed || input[0].Suppression.Suppressed {
		t.Fatal("new finding suppressed or input mutated")
	}
}

func TestKeepReasonsCarriesHandWrittenReasons(t *testing.T) {
	a := finding(t, "sql", "app.py", 10, "x", core.SeverityHigh, core.ConfidenceHigh)
	b := finding(t, "xss", "web.js", 3, "y", core.SeverityMedium, core.ConfidenceHigh)
	previous := NewBaseline([]core.Finding{a})
	previous.Findings[0].Reason = "accepted risk"
	refreshed := NewBaseline([]core.Finding{a, b}).KeepReasons(previous)
	reasons := map[string]string{}
	for _, entry := range refreshed.Findings {
		reasons[entry.Rule] = entry.Reason
	}
	if reasons["sql"] != "accepted risk" || reasons["xss"] != "" {
		t.Fatalf("reasons=%v", reasons)
	}
}

func TestLoadBaselineRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"version":  `{"version": 2, "findings": []}`,
		"unknown":  `{"version": 1, "findings": [], "extra": true}`,
		"key":      `{"version": 1, "findings": [{"key": "plain", "rule": "r", "path": "p", "severity": "high", "message": "m"}]}`,
		"not-json": `version: 1`,
	}
	for name, content := range cases {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBaseline(dir, name+".json"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := LoadBaseline(dir, "missing.json"); err == nil {
		t.Error("missing file accepted")
	}
}

func TestBaselineFilesMustStayInsideProject(t *testing.T) {
	outside := t.TempDir()
	project := t.TempDir()
	secret := filepath.Join(outside, "secret.json")
	valid := `{"version": 1, "findings": []}`
	if err := os.WriteFile(secret, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(project, "linked.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	relativeEscape, err := filepath.Rel(project, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{relativeEscape, secret, "linked.json"} {
		if _, err := LoadBaseline(project, name); err == nil {
			t.Errorf("LoadBaseline(%q) read a file outside the project", name)
		}
	}
	if err := WriteBaseline(project, relativeEscape, Baseline{Version: BaselineVersion}); err == nil {
		t.Error("WriteBaseline escaped the project")
	}
	// Replacing a link swaps the link itself for a regular file; the target is untouched.
	if err := WriteBaseline(project, "linked.json", Baseline{Version: BaselineVersion}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(project, "linked.json")); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("link not replaced by a regular file: %v %v", info, err)
	}
	if data, _ := os.ReadFile(secret); string(data) != valid {
		t.Fatalf("outside file modified: %s", data)
	}
}

func TestWriteFileAtomicReplacesWithoutLeavingTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.sarif")
	for _, content := range []string{"first", "second"} {
		if err := WriteFileAtomic(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "second" {
		t.Fatalf("content=%q err=%v", data, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
	if err := WriteFileAtomic(filepath.Join(dir, "missing", "x"), []byte("x")); err == nil {
		t.Fatal("write into missing directory succeeded")
	}
}

func TestParseGate(t *testing.T) {
	for _, value := range []string{"", "none", "NONE"} {
		gate, err := ParseGate(value, "")
		if err != nil || gate.Enabled() {
			t.Errorf("%q: gate=%+v err=%v", value, gate, err)
		}
	}
	gate, err := ParseGate("High", "Medium")
	if err != nil || gate.FailOn != core.SeverityHigh || gate.MinConfidence != core.ConfidenceMedium {
		t.Fatalf("gate=%+v err=%v", gate, err)
	}
	for _, bad := range [][2]string{{"severe", ""}, {"high", "certain"}} {
		if _, err := ParseGate(bad[0], bad[1]); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestGateBlockingRespectsThresholdsAndSuppression(t *testing.T) {
	critical := finding(t, "a", "a.py", 1, "a", core.SeverityCritical, core.ConfidenceLow)
	high := finding(t, "b", "b.py", 1, "b", core.SeverityHigh, core.ConfidenceHigh)
	medium := finding(t, "c", "c.py", 1, "c", core.SeverityMedium, core.ConfidenceHigh)
	accepted := finding(t, "d", "d.py", 1, "d", core.SeverityCritical, core.ConfidenceHigh)
	accepted.Suppression = core.Suppression{Suppressed: true, Reason: "baseline"}
	findings := []core.Finding{critical, high, medium, accepted}

	rules := func(blocking []core.Finding) []string {
		var out []string
		for _, f := range blocking {
			out = append(out, f.Rule)
		}
		return out
	}
	cases := []struct {
		failOn, confidence string
		want               []string
	}{
		{"none", "", nil},
		{"high", "", []string{"a", "b"}},
		{"high", "high", []string{"b"}},
		{"medium", "medium", []string{"b", "c"}},
		{"info", "low", []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		gate, err := ParseGate(tc.failOn, tc.confidence)
		if err != nil {
			t.Fatal(err)
		}
		if got := rules(gate.Blocking(findings)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("fail-on=%s confidence=%s blocking=%v want %v", tc.failOn, tc.confidence, got, tc.want)
		}
	}
}

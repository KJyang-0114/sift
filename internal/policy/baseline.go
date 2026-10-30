// Package policy applies project decisions to scan results: accepted-finding
// baselines and the severity gate that decides whether a scan blocks CI.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KJyang-0114/sift/internal/core"
)

// BaselineVersion identifies the serialized baseline format.
const BaselineVersion = 1

// Baseline records findings a project has accepted. Entries match by a key that
// ignores line numbers, so unrelated edits above a finding do not resurface it.
type Baseline struct {
	Version  int             `json:"version"`
	Findings []BaselineEntry `json:"findings"`
}

// BaselineEntry is one accepted finding. Only Key participates in matching; the
// other fields keep the file reviewable. Reason may be edited by hand.
type BaselineEntry struct {
	Key      string        `json:"key"`
	Rule     string        `json:"rule"`
	Path     string        `json:"path"`
	Line     int           `json:"line,omitempty"`
	Severity core.Severity `json:"severity"`
	Message  string        `json:"message"`
	Reason   string        `json:"reason,omitempty"`
}

// NewBaseline accepts every given finding.
func NewBaseline(findings []core.Finding) Baseline {
	keys := BaselineKeys(findings)
	baseline := Baseline{Version: BaselineVersion, Findings: make([]BaselineEntry, len(findings))}
	for i, finding := range findings {
		baseline.Findings[i] = BaselineEntry{
			Key: keys[i], Rule: finding.Rule, Path: finding.Location.Path, Line: finding.Location.Line,
			Severity: finding.Severity, Message: truncate(finding.Message, 200),
		}
	}
	sort.Slice(baseline.Findings, func(i, j int) bool {
		a, b := baseline.Findings[i], baseline.Findings[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Key < b.Key
	})
	return baseline
}

// KeepReasons copies hand-written reasons from a previous baseline for keys that remain.
func (b Baseline) KeepReasons(previous Baseline) Baseline {
	reasons := map[string]string{}
	for _, entry := range previous.Findings {
		if entry.Reason != "" {
			reasons[entry.Key] = entry.Reason
		}
	}
	for i := range b.Findings {
		if reason, ok := reasons[b.Findings[i].Key]; ok {
			b.Findings[i].Reason = reason
		}
	}
	return b
}

// LoadBaseline reads and validates a baseline file.
func LoadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline: %w", err)
	}
	var baseline Baseline
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if baseline.Version != BaselineVersion {
		return Baseline{}, fmt.Errorf("baseline %s has unsupported version %d (want %d)", path, baseline.Version, BaselineVersion)
	}
	for i, entry := range baseline.Findings {
		if !strings.HasPrefix(entry.Key, "sha256:") {
			return Baseline{}, fmt.Errorf("baseline %s entry %d has an invalid key", path, i)
		}
	}
	return baseline, nil
}

// WriteBaseline atomically replaces path with the serialized baseline.
func WriteBaseline(path string, baseline Baseline) error {
	if baseline.Findings == nil {
		baseline.Findings = []BaselineEntry{}
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(data, '\n'))
}

// Apply marks findings matched by the baseline as suppressed without removing
// them, keeping the decision visible in reports. It returns the updated findings,
// how many were suppressed, and how many baseline entries no longer match.
func (b Baseline) Apply(findings []core.Finding, source string) ([]core.Finding, int, int) {
	reasons := make(map[string]string, len(b.Findings))
	for _, entry := range b.Findings {
		reason := strings.TrimSpace(entry.Reason)
		if reason == "" {
			reason = "accepted in baseline " + source
		}
		reasons[entry.Key] = reason
	}
	updated := make([]core.Finding, len(findings))
	copy(updated, findings)
	matched := map[string]bool{}
	suppressed := 0
	for i, key := range BaselineKeys(findings) {
		reason, ok := reasons[key]
		if !ok {
			continue
		}
		matched[key] = true
		if !updated[i].Suppression.Suppressed {
			updated[i].Suppression = core.Suppression{Suppressed: true, Reason: "baseline: " + reason}
			suppressed++
		}
	}
	return updated, suppressed, len(reasons) - len(matched)
}

// BaselineKeys derives a line-independent key per finding from its source, rule,
// path and whitespace-normalized evidence. Identical findings in one file are
// distinguished by their order of appearance.
func BaselineKeys(findings []core.Finding) []string {
	bases := make([]string, len(findings))
	groups := map[string][]int{}
	for i, finding := range findings {
		content := finding.Message
		for _, evidence := range finding.Evidence {
			if strings.TrimSpace(evidence.Snippet) != "" {
				content = evidence.Snippet
				break
			}
		}
		bases[i] = strings.Join([]string{finding.Source, finding.Rule, finding.Location.Path, strings.Join(strings.Fields(content), " ")}, "\x00")
		groups[bases[i]] = append(groups[bases[i]], i)
	}
	keys := make([]string, len(findings))
	for base, indexes := range groups {
		sort.SliceStable(indexes, func(a, b int) bool {
			left, right := findings[indexes[a]].Location, findings[indexes[b]].Location
			if left.Line != right.Line {
				return left.Line < right.Line
			}
			return left.Column < right.Column
		})
		for occurrence, index := range indexes {
			digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", base, occurrence)))
			keys[index] = "sha256:" + hex.EncodeToString(digest[:])
		}
	}
	return keys
}

// WriteFileAtomic writes through a temporary file in the destination directory so
// readers never observe a partially written report or baseline.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		os.Remove(name)
		return err
	}
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		os.Remove(name)
		return err
	}
	if err := temp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func truncate(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) <= limit {
		return text
	}
	return strings.ToValidUTF8(text[:limit], "") + "…"
}

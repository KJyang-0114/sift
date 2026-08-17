package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
)

const (
	// FindingSchemaVersion identifies the serialized Finding v2 contract.
	FindingSchemaVersion = "2"
	// MaxEvidenceSnippetBytes bounds source and tool output copied into a finding.
	MaxEvidenceSnippetBytes = 2 * 1024
)

// EvidenceKind identifies the provenance of evidence supporting a finding.
type EvidenceKind string

const (
	EvidenceCode       EvidenceKind = "code"
	EvidenceDependency EvidenceKind = "dependency"
	EvidenceExecution  EvidenceKind = "execution"
	EvidenceModel      EvidenceKind = "model"
	EvidenceOther      EvidenceKind = "other"
)

// Valid reports whether the evidence kind is part of the Finding v2 contract.
func (k EvidenceKind) Valid() bool {
	switch k {
	case EvidenceCode, EvidenceDependency, EvidenceExecution, EvidenceModel, EvidenceOther:
		return true
	default:
		return false
	}
}

// Location identifies a repository-relative source range.
type Location struct {
	Path      string `json:"path"`
	Line      int    `json:"line,omitempty"`
	Column    int    `json:"column,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	EndColumn int    `json:"end_column,omitempty"`
}

// Evidence is a bounded fact supporting a finding.
type Evidence struct {
	Kind        EvidenceKind `json:"kind"`
	Snippet     string       `json:"snippet,omitempty"`
	Description string       `json:"description,omitempty"`
}

// Suppression records audit-visible suppression state.
type Suppression struct {
	Suppressed bool   `json:"suppressed"`
	Reason     string `json:"reason,omitempty"`
}

// Finding is the version 2 normalized security finding contract.
type Finding struct {
	SchemaVersion    string      `json:"schema_version"`
	ID               string      `json:"id"`
	Fingerprint      string      `json:"fingerprint"`
	Source           string      `json:"source"`
	Rule             string      `json:"rule"`
	Message          string      `json:"message"`
	Severity         Severity    `json:"severity"`
	Category         string      `json:"category"`
	Confidence       Confidence  `json:"confidence"`
	Location         Location    `json:"location"`
	RelatedLocations []Location  `json:"related_locations"`
	Evidence         []Evidence  `json:"evidence"`
	Remediation      string      `json:"remediation"`
	HelpURI          string      `json:"help_uri,omitempty"`
	CWE              string      `json:"cwe,omitempty"`
	OWASP            string      `json:"owasp,omitempty"`
	Suppression      Suppression `json:"suppression"`
}

// FindingInput contains analyzer-provided values used to build a Finding.
// StableKey participates in identity generation but is never serialized.
type FindingInput struct {
	Source           string
	Rule             string
	Message          string
	Severity         Severity
	Category         string
	Confidence       Confidence
	Location         Location
	RelatedLocations []Location
	Evidence         []Evidence
	Remediation      string
	HelpURI          string
	CWE              string
	OWASP            string
	Suppression      Suppression
	StableKey        string
}

// NewFinding validates and normalizes analyzer output, then derives stable identity.
func NewFinding(input FindingInput) (Finding, error) {
	input.Source = strings.TrimSpace(input.Source)
	input.Rule = strings.TrimSpace(input.Rule)
	input.Message = strings.TrimSpace(input.Message)
	input.Category = strings.TrimSpace(input.Category)
	input.Remediation = strings.TrimSpace(input.Remediation)

	if input.Source == "" {
		return Finding{}, fmt.Errorf("finding source is required")
	}
	if input.Rule == "" {
		return Finding{}, fmt.Errorf("finding rule is required")
	}
	if input.Message == "" {
		return Finding{}, fmt.Errorf("finding message is required")
	}
	if input.Category == "" {
		return Finding{}, fmt.Errorf("finding category is required")
	}
	if input.Remediation == "" {
		return Finding{}, fmt.Errorf("finding remediation is required")
	}
	if !input.Severity.Valid() {
		return Finding{}, fmt.Errorf("invalid finding severity %q", input.Severity)
	}
	if !input.Confidence.Valid() {
		return Finding{}, fmt.Errorf("invalid finding confidence %q", input.Confidence)
	}

	primary, err := normalizeLocation(input.Location)
	if err != nil {
		return Finding{}, fmt.Errorf("invalid primary location: %w", err)
	}
	related := make([]Location, len(input.RelatedLocations))
	for i, location := range input.RelatedLocations {
		related[i], err = normalizeLocation(location)
		if err != nil {
			return Finding{}, fmt.Errorf("invalid related location %d: %w", i, err)
		}
	}

	if len(input.Evidence) == 0 {
		return Finding{}, fmt.Errorf("at least one evidence item is required")
	}
	evidence := make([]Evidence, len(input.Evidence))
	copy(evidence, input.Evidence)
	for i := range evidence {
		if !evidence[i].Kind.Valid() {
			return Finding{}, fmt.Errorf("invalid evidence kind %q", evidence[i].Kind)
		}
		if evidence[i].Snippet == "" && strings.TrimSpace(evidence[i].Description) == "" {
			return Finding{}, fmt.Errorf("evidence %d has no snippet or description", i)
		}
		if len(evidence[i].Snippet) > MaxEvidenceSnippetBytes {
			return Finding{}, fmt.Errorf("evidence %d snippet exceeds %d bytes", i, MaxEvidenceSnippetBytes)
		}
	}

	stableKey := strings.TrimSpace(input.StableKey)
	if stableKey == "" {
		stableKey = fmt.Sprintf("%d:%d:%s", primary.Line, primary.Column, input.Message)
	}
	identity := strings.Join([]string{input.Source, input.Rule, primary.Path, stableKey}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	hexDigest := hex.EncodeToString(digest[:])

	return Finding{
		SchemaVersion:    FindingSchemaVersion,
		ID:               fmt.Sprintf("%s/%s/%s", input.Source, input.Rule, hexDigest[:16]),
		Fingerprint:      "sha256:" + hexDigest,
		Source:           input.Source,
		Rule:             input.Rule,
		Message:          input.Message,
		Severity:         input.Severity,
		Category:         input.Category,
		Confidence:       input.Confidence,
		Location:         primary,
		RelatedLocations: related,
		Evidence:         evidence,
		Remediation:      input.Remediation,
		HelpURI:          strings.TrimSpace(input.HelpURI),
		CWE:              strings.TrimSpace(input.CWE),
		OWASP:            strings.TrimSpace(input.OWASP),
		Suppression:      input.Suppression,
	}, nil
}

func normalizeLocation(location Location) (Location, error) {
	normalized := strings.ReplaceAll(strings.TrimSpace(location.Path), "\\", "/")
	if normalized == "" {
		return Location{}, fmt.Errorf("path is required")
	}
	if strings.HasPrefix(normalized, "/") || hasWindowsVolume(normalized) {
		return Location{}, fmt.Errorf("path must be repository-relative")
	}
	normalized = path.Clean(normalized)
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return Location{}, fmt.Errorf("path escapes repository root")
	}
	if location.Line < 0 || location.Column < 0 || location.EndLine < 0 || location.EndColumn < 0 {
		return Location{}, fmt.Errorf("line and column values cannot be negative")
	}
	location.Path = normalized
	return location, nil
}

func hasWindowsVolume(path string) bool {
	return len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && path[2] == '/'
}

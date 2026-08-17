package core

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// ScanRequest is an immutable analyzer request. Targets are repository-relative.
type ScanRequest struct {
	root    string
	targets []string
}

// NewScanRequest validates and defensively copies analyzer targets.
func NewScanRequest(root string, targets []string) (ScanRequest, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "." || root == "" || !filepath.IsAbs(root) {
		return ScanRequest{}, fmt.Errorf("scan root must be an absolute path")
	}
	if len(targets) == 0 {
		return ScanRequest{}, fmt.Errorf("at least one scan target is required")
	}

	normalized := make([]string, len(targets))
	for i, target := range targets {
		var err error
		normalized[i], err = normalizeTarget(target)
		if err != nil {
			return ScanRequest{}, fmt.Errorf("invalid scan target %d: %w", i, err)
		}
	}

	return ScanRequest{root: root, targets: normalized}, nil
}

// Root returns the absolute repository root.
func (request ScanRequest) Root() string {
	return request.root
}

// Targets returns a defensive copy of repository-relative targets.
func (request ScanRequest) Targets() []string {
	targets := make([]string, len(request.targets))
	copy(targets, request.targets)
	return targets
}

// AbsoluteTargets returns target paths joined to the repository root.
func (request ScanRequest) AbsoluteTargets() []string {
	targets := make([]string, len(request.targets))
	for i, target := range request.targets {
		targets[i] = filepath.Join(request.root, filepath.FromSlash(target))
	}
	return targets
}

func normalizeTarget(target string) (string, error) {
	target = strings.ReplaceAll(strings.TrimSpace(target), "\\", "/")
	if target == "" {
		return "", fmt.Errorf("target is required")
	}
	if strings.HasPrefix(target, "/") || hasWindowsVolume(target) {
		return "", fmt.Errorf("target must be repository-relative")
	}
	target = path.Clean(target)
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", fmt.Errorf("target escapes repository root")
	}
	return target, nil
}

// DiagnosticKind identifies the layer that produced a non-finding diagnostic.
type DiagnosticKind string

const (
	DiagnosticConfiguration DiagnosticKind = "configuration"
	DiagnosticPolicy        DiagnosticKind = "policy"
	DiagnosticTarget        DiagnosticKind = "target"
	DiagnosticAnalyzer      DiagnosticKind = "analyzer"
	DiagnosticIntegration   DiagnosticKind = "integration"
	DiagnosticInternal      DiagnosticKind = "internal"
)

// Valid reports whether the diagnostic kind is part of the v2 contract.
func (kind DiagnosticKind) Valid() bool {
	switch kind {
	case DiagnosticConfiguration, DiagnosticPolicy, DiagnosticTarget, DiagnosticAnalyzer, DiagnosticIntegration, DiagnosticInternal:
		return true
	default:
		return false
	}
}

// DiagnosticSeverity expresses the operational impact of a diagnostic.
type DiagnosticSeverity string

const (
	DiagnosticInfo    DiagnosticSeverity = "info"
	DiagnosticWarning DiagnosticSeverity = "warning"
	DiagnosticError   DiagnosticSeverity = "error"
)

// Valid reports whether the diagnostic severity is part of the v2 contract.
func (severity DiagnosticSeverity) Valid() bool {
	switch severity {
	case DiagnosticInfo, DiagnosticWarning, DiagnosticError:
		return true
	default:
		return false
	}
}

// Diagnostic records an expected non-finding condition.
type Diagnostic struct {
	Kind     DiagnosticKind     `json:"kind"`
	Severity DiagnosticSeverity `json:"severity"`
	Code     string             `json:"code"`
	Source   string             `json:"source,omitempty"`
	Message  string             `json:"message"`
	Path     string             `json:"path,omitempty"`
	Cause    error              `json:"-"`
}

// AnalysisResult contains all output from one analyzer invocation.
type AnalysisResult struct {
	Findings    []Finding    `json:"findings"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// Analyzer is the version 2 contract for all analysis implementations.
type Analyzer interface {
	Name() string
	Analyze(context.Context, ScanRequest) AnalysisResult
}

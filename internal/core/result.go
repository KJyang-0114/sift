package core

import (
	"fmt"
	"time"
)

// OperationError identifies a failed operation without coupling it to CLI exit codes.
type OperationError struct {
	Kind DiagnosticKind
	Err  error
}

func (e *OperationError) Error() string { return e.Err.Error() }
func (e *OperationError) Unwrap() error { return e.Err }

// ScanResult retains successful findings even when an analyzer could not finish.
type ScanResult struct {
	AnalysisResult
	Target   string
	Duration time.Duration
}

// HasErrors reports whether required analysis was incomplete.
func (r AnalysisResult) HasErrors() bool {
	for _, diagnostic := range r.Diagnostics {
		if diagnostic.Severity == DiagnosticError {
			return true
		}
	}
	return false
}

// Status is shared by machine-readable and human-readable reports.
func (r AnalysisResult) Status() string {
	if r.HasErrors() {
		return "partial"
	}
	return "complete"
}

// Err is evaluated after rendering so incomplete scans still deliver their results.
func (r ScanResult) Err() error {
	if r.HasErrors() {
		return &OperationError{Kind: DiagnosticAnalyzer, Err: fmt.Errorf("scan incomplete; see report diagnostics")}
	}
	return nil
}

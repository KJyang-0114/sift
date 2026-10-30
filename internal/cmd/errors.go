package cmd

import (
	"errors"
	"fmt"

	"github.com/KJyang-0114/sift/internal/core"
)

func usageError(err error) error {
	return &core.OperationError{Kind: core.DiagnosticConfiguration, Err: err}
}

// gateError reports findings that violate --fail-on after the report was written.
type gateError struct {
	blocking int
}

func (e *gateError) Error() string {
	return fmt.Sprintf("%d finding(s) violate the --fail-on policy", e.blocking)
}

// ExitCode is the process boundary for typed operation failures.
// Code 1 is the finding policy gate; without --fail-on findings stay advisory.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var gate *gateError
	if errors.As(err, &gate) {
		return 1
	}
	var operation *core.OperationError
	if errors.As(err, &operation) {
		switch operation.Kind {
		case core.DiagnosticConfiguration, core.DiagnosticPolicy, core.DiagnosticTarget:
			return 2
		case core.DiagnosticAnalyzer, core.DiagnosticIntegration:
			return 3
		case core.DiagnosticInternal:
			return 4
		}
	}
	return 4
}

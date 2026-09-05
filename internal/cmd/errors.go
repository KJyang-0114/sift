package cmd

import (
	"errors"

	"github.com/KJyang-0114/sift/internal/core"
)

func usageError(err error) error {
	return &core.OperationError{Kind: core.DiagnosticConfiguration, Err: err}
}

// ExitCode is the process boundary for typed operation failures.
// Code 1 remains reserved for finding policy gates; findings are advisory today.
func ExitCode(err error) int {
	if err == nil {
		return 0
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

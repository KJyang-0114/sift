package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/KJyang-0114/sift/internal/core"

	"github.com/spf13/cobra"
)

// Execute classifies Cobra routing/usage failures before a command starts.
// Operational errors returned by command handlers retain their own classification.
func Execute(ctx context.Context, version, commit, date string, args []string, stdout, stderr io.Writer) error {
	root := NewRootCmd(version, commit, date)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	started := false
	root.PersistentPreRun = func(*cobra.Command, []string) { started = true }
	err := root.ExecuteContext(ctx)
	var operation *core.OperationError
	if err != nil && !started && !errors.As(err, &operation) {
		return usageError(err)
	}
	return err
}

// NewRootCmd creates the root command for sift CLI.
func NewRootCmd(version, commit, date string) *cobra.Command {
	root := &cobra.Command{
		Use:   "sift",
		Short: "Sift — AI-powered code security scanner",
		Long: `Sift is an open-source, self-contained (bring your own API key) code security scanner.
	It combines Semgrep static rules with LLM semantic analysis to detect vulnerabilities,
	hallucinated packages, and logic errors.

	One command to scan: sift scan .
	One command to configure: sift init`,
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().String("config", "", "config file path (default ~/.sift/config.toml)")
	root.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	root.PersistentFlags().BoolP("quiet", "q", false, "suppress terminal report, only show diagnostics")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError(err) })

	root.AddCommand(newInitCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newFixCmd())
	root.AddCommand(newConfigCmd())

	return root
}

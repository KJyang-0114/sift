package cmd

import (
	"context"
	"fmt"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/report"
	"github.com/KJyang-0114/sift/internal/scan"
	"github.com/spf13/cobra"
)

type scanService interface {
	SetDiffMode(string)
	Scan(context.Context, string) (core.ScanResult, error)
}

func newScanCmd() *cobra.Command {
	return newScanCmdWithFactory(func(cfg *config.Config) scanService { return scan.NewOrchestrator(cfg) })
}

func newScanCmdWithFactory(factory func(*config.Config) scanService) *cobra.Command {
	var format, sandbox, diffRef string
	var timeout int
	command := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan code for security vulnerabilities",
		Long: `Scan directories, single files, or tracked Git changes with static rules,
package verification, and configured optional analyzers.
Findings are advisory. Incomplete analysis returns exit code 3.`,
		Args: func(command *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(command, args); err != nil {
				return usageError(err)
			}
			return nil
		},
		RunE: func(command *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}
			cfgPath, _ := command.Flags().GetString("config")
			cfg, _, err := config.LoadFile(cfgPath)
			if err != nil {
				return usageError(err)
			}
			if command.Flags().Changed("timeout") {
				cfg.Scan.Timeout = timeout
			}
			if command.Flags().Changed("sandbox") {
				cfg.Scan.Sandbox = sandbox
			}
			if command.Flags().Changed("format") {
				cfg.Output.Format = format
			}
			if err := cfg.Validate(); err != nil {
				return usageError(err)
			}
			quiet, _ := command.Flags().GetBool("quiet")
			verbose, _ := command.Flags().GetBool("verbose")
			if quiet && verbose {
				return usageError(fmt.Errorf("--quiet and --verbose cannot be used together"))
			}
			if command.Flags().Changed("diff") && diffRef == "" {
				return usageError(fmt.Errorf("git diff reference must not be empty"))
			}
			service := factory(cfg)
			if command.Flags().Changed("diff") {
				service.SetDiffMode(diffRef)
			}
			result, err := service.Scan(command.Context(), target)
			if err != nil {
				return err
			}
			// Diagnostics stay inside every report. Mirror them to stderr for pipelines
			// and quiet terminal use, without duplicating the normal terminal report.
			if quiet || cfg.Output.Format == "json" || cfg.Output.Format == "sarif" {
				for _, diagnostic := range result.Diagnostics {
					fmt.Fprintf(command.ErrOrStderr(), "%s [%s] %s: %s\n", diagnostic.Severity, diagnostic.Code, diagnostic.Source, diagnostic.Message)
				}
			}
			if verbose {
				fmt.Fprintf(command.ErrOrStderr(), "scan status=%s findings=%d diagnostics=%d duration=%s\n", result.Status(), len(result.Findings), len(result.Diagnostics), result.Duration)
			}
			// Quiet never removes a machine-readable report from a pipeline.
			if !quiet || cfg.Output.Format != "terminal" {
				if err := report.NewEngine(cfg).Render(command.OutOrStdout(), result.Findings, result.Diagnostics, result.Target, result.Duration, cfg.Output.Format); err != nil {
					return &core.OperationError{Kind: core.DiagnosticInternal, Err: fmt.Errorf("write %s report: %w", cfg.Output.Format, err)}
				}
			}
			return result.Err()
		},
	}
	command.Flags().StringVarP(&format, "format", "f", "terminal", "output format (terminal|json|sarif|llm)")
	command.Flags().StringVar(&sandbox, "sandbox", "orbital", "sandbox mode (orbital)")
	command.Flags().IntVarP(&timeout, "timeout", "t", 120, "max scan seconds per analyzer")
	command.Flags().StringVar(&diffRef, "diff", "", "scan tracked changes against a commit (default: HEAD; excludes untracked/deleted files)")
	command.Flags().Lookup("diff").NoOptDefVal = "HEAD"
	return command
}

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/policy"
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
	var format, sandbox, diffRef, failOn, minConfidence, baselinePath, writeBaselinePath, outputPath string
	var timeout int
	command := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan code for security vulnerabilities",
		Long: `Scan directories, single files, or tracked Git changes with static rules,
package verification, and configured optional analyzers.
Findings are advisory unless --fail-on is set, which returns exit code 1 when an
unsuppressed finding reaches the threshold. Incomplete analysis returns exit code 3.
--baseline suppresses previously accepted findings; --write-baseline accepts all
current findings. Reports are always written before the exit code is returned.`,
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
			gate, err := policy.ParseGate(failOn, minConfidence)
			if err != nil {
				return usageError(err)
			}
			// Baselines are project policy: reads and writes stay inside the working directory.
			projectDir, err := os.Getwd()
			if err != nil {
				return &core.OperationError{Kind: core.DiagnosticInternal, Err: fmt.Errorf("resolve working directory: %w", err)}
			}
			var baseline *policy.Baseline
			if baselinePath != "" {
				loaded, err := policy.LoadBaseline(projectDir, baselinePath)
				if err != nil {
					return usageError(err)
				}
				baseline = &loaded
			}
			service := factory(cfg)
			if command.Flags().Changed("diff") {
				service.SetDiffMode(diffRef)
			}
			result, err := service.Scan(command.Context(), target)
			if err != nil {
				return err
			}
			stderr := command.ErrOrStderr()
			var baselineErr error
			if writeBaselinePath != "" {
				written := policy.NewBaseline(result.Findings)
				if baseline != nil {
					written = written.KeepReasons(*baseline)
				}
				if err := policy.WriteBaseline(projectDir, writeBaselinePath, written); err != nil {
					baselineErr = &core.OperationError{Kind: core.DiagnosticInternal, Err: fmt.Errorf("write baseline: %w", err)}
				} else {
					fmt.Fprintf(stderr, "baseline: wrote %d finding(s) to %s\n", len(written.Findings), writeBaselinePath)
					if result.HasErrors() {
						fmt.Fprintln(stderr, "baseline: scan was partial; findings from failed analyzers are not included")
					}
					baseline, baselinePath = &written, writeBaselinePath
				}
			}
			if baseline != nil {
				var suppressed, stale int
				result.Findings, suppressed, stale = baseline.Apply(result.Findings, baselinePath)
				if verbose {
					fmt.Fprintf(stderr, "baseline: suppressed=%d stale=%d\n", suppressed, stale)
				}
			}
			// Diagnostics stay inside every report. Mirror them to stderr for pipelines
			// and quiet terminal use, without duplicating the normal terminal report.
			machine := cfg.Output.Format == "json" || cfg.Output.Format == "sarif"
			if quiet || (machine && outputPath == "") {
				for _, diagnostic := range result.Diagnostics {
					fmt.Fprintf(stderr, "%s [%s] %s: %s\n", diagnostic.Severity, diagnostic.Code, diagnostic.Source, diagnostic.Message)
				}
			}
			if verbose {
				fmt.Fprintf(stderr, "scan status=%s findings=%d diagnostics=%d duration=%s\n", result.Status(), len(result.Findings), len(result.Diagnostics), result.Duration)
			}
			render := func(w io.Writer, format string, color bool) error {
				renderCfg := *cfg
				renderCfg.Output.Color = color
				if err := report.NewEngine(&renderCfg).Render(w, result.Findings, result.Diagnostics, result.Target, result.Duration, format); err != nil {
					return &core.OperationError{Kind: core.DiagnosticInternal, Err: fmt.Errorf("write %s report: %w", format, err)}
				}
				return nil
			}
			if outputPath != "" {
				// The file receives the selected format; the terminal still shows a readable report.
				var buffer bytes.Buffer
				if err := render(&buffer, cfg.Output.Format, cfg.Output.Format != "terminal" && cfg.Output.Color); err != nil {
					return err
				}
				if err := policy.WriteFileAtomic(outputPath, buffer.Bytes()); err != nil {
					return &core.OperationError{Kind: core.DiagnosticInternal, Err: fmt.Errorf("write %s report to %s: %w", cfg.Output.Format, outputPath, err)}
				}
				if !quiet && cfg.Output.Format != "terminal" {
					if err := render(command.OutOrStdout(), "terminal", cfg.Output.Color); err != nil {
						return err
					}
				}
			} else if !quiet || cfg.Output.Format != "terminal" {
				// Quiet never removes a machine-readable report from a pipeline.
				if err := render(command.OutOrStdout(), cfg.Output.Format, cfg.Output.Color); err != nil {
					return err
				}
			}
			if baselineErr != nil {
				return baselineErr
			}
			if blocking := gate.Blocking(result.Findings); len(blocking) > 0 {
				fmt.Fprintf(stderr, "gate: %d finding(s) at or above %s with %s+ confidence block this scan\n", len(blocking), gate.FailOn, gate.MinConfidence)
				for i, finding := range blocking {
					if i == 5 {
						fmt.Fprintf(stderr, "  ... and %d more\n", len(blocking)-5)
						break
					}
					fmt.Fprintf(stderr, "  - [%s] %s %s:%d\n", finding.Severity, finding.Rule, finding.Location.Path, finding.Location.Line)
				}
				return &gateError{blocking: len(blocking)}
			}
			return result.Err()
		},
	}
	command.Flags().StringVarP(&format, "format", "f", "terminal", "output format (terminal|json|sarif|llm)")
	command.Flags().StringVar(&sandbox, "sandbox", "orbital", "sandbox mode (orbital)")
	command.Flags().IntVarP(&timeout, "timeout", "t", 120, "max scan seconds per analyzer")
	command.Flags().StringVar(&diffRef, "diff", "", "scan tracked changes against a commit (default: HEAD; excludes untracked/deleted files)")
	command.Flags().Lookup("diff").NoOptDefVal = "HEAD"
	command.Flags().StringVar(&failOn, "fail-on", "none", "exit 1 when an unsuppressed finding reaches this severity (critical|high|medium|low|info|none)")
	command.Flags().StringVar(&minConfidence, "min-confidence", "medium", "minimum finding confidence counted by --fail-on (high|medium|low)")
	command.Flags().StringVar(&baselinePath, "baseline", "", "suppress findings accepted in this baseline file")
	command.Flags().StringVar(&writeBaselinePath, "write-baseline", "", "write all current findings to this baseline file (keeps reasons from --baseline)")
	command.Flags().StringVarP(&outputPath, "output", "o", "", "write the --format report to this file and show the terminal report on stdout")
	return command
}

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/KJyang-0114/sift/internal/agent"
	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/core"
	"github.com/KJyang-0114/sift/internal/scan"
	"github.com/spf13/cobra"
)

type fixScanService interface {
	RunTo(context.Context, string, string, io.Writer) error
	LastFindings() []core.Finding
}

func newFixCmd() *cobra.Command {
	return newFixCmdWithFactory(func(cfg *config.Config) fixScanService { return scan.NewOrchestrator(cfg) })
}

func newFixCmdWithFactory(factory func(*config.Config) fixScanService) *cobra.Command {
	var (
		auto        bool
		interactive bool
		dryRun      bool
		rollback    bool
	)

	cmd := &cobra.Command{
		Use:   "fix [path]",
		Short: "Automatically scan and fix security vulnerabilities",
		Long: `fix first runs a full security scan, then generates fix suggestions for each finding.

	Modes:
	  sift fix .                scan + show fix suggestions (no apply)
	  sift fix . --auto         scan + auto-apply all fixes
	  sift fix . --interactive  scan + confirm each fix before applying`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			if rollback {
				if len(args) != 1 {
					return usageError(fmt.Errorf("rollback requires one file path"))
				}
				absolute, err := filepath.Abs(target)
				if err != nil {
					return usageError(err)
				}
				if err := agent.RollbackFile(filepath.Dir(absolute), filepath.Base(absolute)); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Restored:", target)
				return nil
			}
			// Load configuration
			cfgPath, _ := cmd.Flags().GetString("config")
			cfg, _, err := config.LoadFile(cfgPath)
			if err != nil {
				return usageError(err)
			}
			if err := cfg.Validate(); err != nil {
				return usageError(err)
			}

			// Phase 1: Scan
			fmt.Fprintln(cmd.OutOrStdout(), "  🔍 Phase 1: Scanning for security vulnerabilities...")
			orch := factory(cfg)
			scanErr := orch.RunTo(cmd.Context(), target, "terminal", cmd.OutOrStdout())
			if err := scanErr; err != nil {
				if ExitCode(err) != 3 {
					return err
				}
				// Even if scan partially fails, continue with fix attempt
				fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠️  Scan partially failed: %v\n", err)
			}

			// Phase 2: Retrieve findings and fix
			// Reuse the findings from the completed scan.
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "  🔧 Phase 2: Generating fix suggestions...")
			findings := orch.LastFindings()
			if len(findings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No fix suggestions available from completed analysis.")
				return scanErr
			}

			fixer, err := agent.NewFixer(cfg, fixRoot(target))
			if err != nil {
				return fmt.Errorf("cannot initialize fixer: %w", err)
			}

			results := fixer.FixContext(cmd.Context(), findings)
			var fixErr error

			fixedCount := 0
			for i, r := range results {
				if !r.Generated {
					fixErr = errors.Join(fixErr, fmt.Errorf("generate %s: %s", r.Finding.Location.Path, r.Error))
					fmt.Fprintf(cmd.OutOrStdout(), "  ❌ [%d/%d] %s: %s\n", i+1, len(results), r.Finding.Location.Path, r.Error)
					continue
				}

				if dryRun {
					fmt.Fprintf(cmd.OutOrStdout(), "  📝 [%d/%d] %s:%d — %s\n", i+1, len(results), r.Finding.Location.Path, r.Finding.Location.Line, r.Finding.Rule)
					fmt.Fprintf(cmd.OutOrStdout(), "     %s\n", truncateLines(r.Patch, 3))
					continue
				}

				if interactive {
					fmt.Fprintf(cmd.OutOrStdout(), "\n  ── Fix [%d/%d] ──\n", i+1, len(results))
					fmt.Fprintf(cmd.OutOrStdout(), "  File: %s:%d\n", r.Finding.Location.Path, r.Finding.Location.Line)
					fmt.Fprintf(cmd.OutOrStdout(), "  Issue: %s\n", r.Finding.Message)
					fmt.Fprintf(cmd.OutOrStdout(), "  Fix:\n%s\n", r.Patch)
					fmt.Fprint(cmd.OutOrStdout(), "  Apply this fix? [y/N/a(ll)/q(uit)]: ")

					var answer string
					fmt.Fscanln(cmd.InOrStdin(), &answer)
					switch answer {
					case "q":
						fmt.Fprintln(cmd.OutOrStdout(), "  Cancelled.")
						goto done
					case "a":
						interactive = false
						auto = true
						fallthrough
					case "y", "Y":
						if err := fixer.ApplyFix(r); err != nil {
							fixErr = errors.Join(fixErr, err)
							fmt.Fprintf(cmd.OutOrStdout(), "  ❌ Apply failed: %v\n", err)
						} else {
							fmt.Fprintln(cmd.OutOrStdout(), "  ✅ Applied")
							fixedCount++
						}
					default:
						fmt.Fprintln(cmd.OutOrStdout(), "  ⏭️  Skipped")
					}
				} else if auto {
					if err := fixer.ApplyFix(r); err != nil {
						fixErr = errors.Join(fixErr, err)
						fmt.Fprintf(cmd.OutOrStdout(), "  ❌ [%d/%d] Apply failed: %v\n", i+1, len(results), err)
					} else {
						fmt.Fprintf(cmd.OutOrStdout(), "  ✅ [%d/%d] Applied: %s:%d\n", i+1, len(results), r.Finding.Location.Path, r.Finding.Location.Line)
						fixedCount++
					}
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "  📝 [%d/%d] %s:%d\n     %s\n", i+1, len(results), r.Finding.Location.Path, r.Finding.Location.Line, truncateLines(r.Patch, 3))
				}
			}

		done:
			fmt.Fprintf(cmd.OutOrStdout(), "\n  📊 Fix complete: %d/%d patches applied (not test-verified)\n", fixedCount, len(results))
			if !dryRun && fixedCount > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "  💡 To revert fixes: sift fix <file> --rollback")
				fmt.Fprintln(cmd.OutOrStdout(), "  💡 Re-scan to verify: sift scan .")
			}

			if fixErr != nil {
				return &core.OperationError{Kind: core.DiagnosticAnalyzer, Err: errors.Join(scanErr, fixErr)}
			}
			return scanErr
		},
	}

	cmd.Flags().BoolVar(&auto, "auto", false, "auto-apply all fixes")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "confirm each fix interactively")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show fix suggestions without applying")

	cmd.Flags().BoolVar(&rollback, "rollback", false, "restore one file from its .sift.bak backup; no model required")
	cmd.MarkFlagsMutuallyExclusive("auto", "interactive", "dry-run", "rollback")
	return cmd
}

func truncateLines(s string, maxLines int) string {
	lines := splitLines(s)
	if len(lines) <= maxLines {
		return s
	}
	return joinLines(lines[:maxLines]) + "\n     ..."
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func joinLines(lines []string) string {
	result := ""
	for i, l := range lines {
		if i > 0 {
			result += "\n     "
		}
		result += l
	}
	return result
}

func fixRoot(target string) string {
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		return filepath.Dir(target)
	}
	return target
}

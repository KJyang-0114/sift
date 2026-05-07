package cmd

import (
	"fmt"
	"os"

	"github.com/KJyang-0114/sift/internal/agent"
	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/scan"
	"github.com/spf13/cobra"
)

func newFixCmd() *cobra.Command {
	var (
		auto        bool
		interactive bool
		dryRun      bool
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

			// Load configuration
			cfg, _, err := config.Load()
			if err != nil {
				return err
			}

			// Phase 1: Scan
			fmt.Println("  🔍 Phase 1: Scanning for security vulnerabilities...")
			orch := scan.NewOrchestrator(cfg)
			if err := orch.Run(target, "terminal"); err != nil {
				// Even if scan partially fails, continue with fix attempt
				fmt.Fprintf(os.Stderr, "  ⚠️  Scan partially failed: %v\n", err)
			}

			// Phase 2: Retrieve findings and fix
			// Re-scan to get structured results
			fmt.Println()
			fmt.Println("  🔧 Phase 2: Generating fix suggestions...")
			findings := orch.LastFindings()
			if len(findings) == 0 {
				fmt.Println("  ✅ No issues to fix!")
				return nil
			}

			fixer, err := agent.NewFixer(cfg)
			if err != nil {
				return fmt.Errorf("cannot initialize fixer: %w", err)
			}

			results := fixer.Fix(findings)

			fixedCount := 0
			for i, r := range results {
				if !r.Fixed {
					fmt.Printf("  ❌ [%d/%d] %s: %s\n", i+1, len(results), r.Finding.File, r.Error)
					continue
				}

				if dryRun {
					fmt.Printf("  📝 [%d/%d] %s:%d — %s\n", i+1, len(results), r.Finding.File, r.Finding.Line, r.Finding.Rule)
					fmt.Printf("     %s\n", truncateLines(r.Patch, 3))
					continue
				}

				if interactive {
					fmt.Printf("\n  ── Fix [%d/%d] ──\n", i+1, len(results))
					fmt.Printf("  File: %s:%d\n", r.Finding.File, r.Finding.Line)
					fmt.Printf("  Issue: %s\n", r.Finding.Message)
					fmt.Printf("  Fix:\n%s\n", r.Patch)
					fmt.Print("  Apply this fix? [y/N/a(ll)/q(uit)]: ")

					var answer string
					fmt.Scanln(&answer)
					switch answer {
					case "q":
						fmt.Println("  Cancelled.")
						goto done
					case "a":
						interactive = false
						fallthrough
					case "y", "Y":
						if err := fixer.ApplyFix(r); err != nil {
							fmt.Printf("  ❌ Apply failed: %v\n", err)
						} else {
							fmt.Println("  ✅ Applied")
							fixedCount++
						}
					default:
						fmt.Println("  ⏭️  Skipped")
					}
				} else if auto {
					if err := fixer.ApplyFix(r); err != nil {
						fmt.Printf("  ❌ [%d/%d] Apply failed: %v\n", i+1, len(results), err)
					} else {
						fmt.Printf("  ✅ [%d/%d] Fixed: %s:%d\n", i+1, len(results), r.Finding.File, r.Finding.Line)
						fixedCount++
					}
				} else {
					fmt.Printf("  📝 [%d/%d] %s:%d\n     %s\n", i+1, len(results), r.Finding.File, r.Finding.Line, truncateLines(r.Patch, 3))
				}
			}

		done:
			fmt.Printf("\n  📊 Fix complete: %d/%d issues fixed\n", fixedCount, len(results))
			if !dryRun && fixedCount > 0 {
				fmt.Println("  💡 To revert fixes: sift fix --rollback")
				fmt.Println("  💡 Re-scan to verify: sift scan .")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&auto, "auto", false, "auto-apply all fixes")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "confirm each fix interactively")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show fix suggestions without applying")

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

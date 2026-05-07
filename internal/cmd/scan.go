package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/KJyang-0114/sift/internal/scan"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		format   string
		sandbox  string
		timeout  int
		diffMode bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan code for security vulnerabilities",
		Long: `scan performs a fully automated security scan on the given path, including:
	  - Static rule scanning (Semgrep)
	  - Hallucinated package detection
	  - Sandbox dynamic testing (optional)

	Supports directories, single files, or Git diff scanning.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			// Path validation: reject paths containing ../ (path traversal protection)
			if strings.Contains(target, "..") {
				return fmt.Errorf("path not allowed: %s", target)
			}

			absTarget, err := filepath.Abs(target)
			if err != nil {
				return fmt.Errorf("cannot resolve path: %w", err)
			}
			if _, err := os.Stat(absTarget); err != nil {
				return fmt.Errorf("path does not exist: %s", absTarget)
			}

			// Load configuration
			cfg, _, err := config.Load()
			if err != nil {
				return err
			}

			// Command-line flags override config
			if cmd.Flags().Changed("timeout") {
				cfg.Scan.Timeout = timeout
			}
			if cmd.Flags().Changed("sandbox") {
				cfg.Scan.Sandbox = sandbox
			}
			if cmd.Flags().Changed("format") {
				cfg.Output.Format = format
			}

			orch := scan.NewOrchestrator(cfg)
			if diffMode {
				orch.SetDiffMode(true)
			}
			if err := orch.Run(absTarget, cfg.Output.Format); err != nil {
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "output format (terminal|json|sarif|llm)")
	cmd.Flags().StringVar(&sandbox, "sandbox", "orbital", "sandbox mode (orbital)")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 120, "max scan seconds per file")
	cmd.Flags().BoolVar(&diffMode, "diff", false, "scan changed files only (git diff)")

	return cmd
}

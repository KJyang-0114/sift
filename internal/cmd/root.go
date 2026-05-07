package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
	quiet   bool
)

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
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default ~/.sift/config.toml)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress output, only show errors")

	root.AddCommand(newInitCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newFixCmd())
	root.AddCommand(newConfigCmd())

	return root
}

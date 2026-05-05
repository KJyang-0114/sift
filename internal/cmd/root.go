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
		Short: "Sift — 全自動 AI 程式碼安全掃描工具",
		Long: `Sift 是一套開源、自帶 API Key 的全自動程式碼安全掃描工具。
它結合 Semgrep 靜態規則與 LLM 語意分析，掃描安全漏洞、幻覺套件、以及邏輯錯誤。

一指令掃描：sift scan .
一指令設定：sift init`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "設定檔路徑 (預設 ~/.sift/config.toml)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "顯示詳細日誌")
	root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "只顯示錯誤")

	root.AddCommand(newInitCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newConfigCmd())

	return root
}

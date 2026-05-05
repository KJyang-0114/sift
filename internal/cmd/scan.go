package cmd

import (
	"fmt"

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
		Short: "掃描程式碼安全漏洞",
		Long: `scan 對指定路徑執行全自動安全掃描，包含：
  - 靜態規則掃描 (Semgrep)
  - LLM 語意分析 (可選)
  - 幻覺套件檢測
  - 沙盒動態測試 (可選)

支援目錄、單一檔案、或 Git diff 掃描。`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}
			fmt.Printf("🔍 掃描中: %s\n", target)
			fmt.Println("(掃描引擎開發中 — 敬請期待 MVP)")
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "輸出格式 (terminal|json|sarif|llm)")
	cmd.Flags().StringVar(&sandbox, "sandbox", "orbital", "沙盒模式 (orbital|docker|firecracker)")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 120, "單檔最大掃描秒數")
	cmd.Flags().BoolVar(&diffMode, "diff", false, "只掃描變更的檔案 (git diff)")

	return cmd
}

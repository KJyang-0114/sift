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
		Short: "掃描程式碼安全漏洞",
		Long: `scan 對指定路徑執行全自動安全掃描，包含：
  - 靜態規則掃描 (Semgrep)
  - 幻覺套件檢測
  - 沙盒動態測試 (可選)

支援目錄、單一檔案、或 Git diff 掃描。`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			// 路徑驗證：拒絕包含 ../ 的路徑（path traversal 防護）
			if strings.Contains(target, "..") {
				return fmt.Errorf("不允許的路徑: %s", target)
			}

			absTarget, err := filepath.Abs(target)
			if err != nil {
				return fmt.Errorf("無法解析路徑: %w", err)
			}
			if _, err := os.Stat(absTarget); err != nil {
				return fmt.Errorf("路徑不存在: %s", absTarget)
			}

			// 載入設定
			cfg, _, err := config.Load()
			if err != nil {
				return err
			}

			// 命令列參數覆蓋設定
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

	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "輸出格式 (terminal|json|sarif|llm)")
	cmd.Flags().StringVar(&sandbox, "sandbox", "orbital", "沙盒模式 (orbital)")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 120, "單檔最大掃描秒數")
	cmd.Flags().BoolVar(&diffMode, "diff", false, "只掃描變更的檔案 (git diff)")

	return cmd
}

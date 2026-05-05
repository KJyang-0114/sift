package cmd

import (
	"fmt"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "檢視或修改設定",
		Long:  `顯示目前設定檔內容與路徑。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, err := config.Load()
			if err != nil {
				return fmt.Errorf("無法載入設定: %w", err)
			}

			fmt.Printf("設定檔路徑: %s\n", path)
			fmt.Println()
			fmt.Printf("[llm]\n")
			fmt.Printf("  provider = %s\n", cfg.LLM.Provider)
			if cfg.LLM.APIKey != "" {
				fmt.Printf("  api_key  = %s***\n", cfg.LLM.APIKey[:min(8, len(cfg.LLM.APIKey))])
			}
			fmt.Printf("  model    = %s\n", cfg.LLM.Model)
			fmt.Println()
			fmt.Printf("[scan]\n")
			fmt.Printf("  timeout     = %d\n", cfg.Scan.Timeout)
			fmt.Printf("  concurrency = %d\n", cfg.Scan.Concurrency)
			fmt.Printf("  sandbox     = %s\n", cfg.Scan.Sandbox)
			fmt.Println()
			fmt.Printf("[output]\n")
			fmt.Printf("  format = %s\n", cfg.Output.Format)
			fmt.Printf("  color  = %v\n", cfg.Output.Color)
			return nil
		},
	}
	return cmd
}

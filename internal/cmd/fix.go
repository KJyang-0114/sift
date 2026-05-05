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
		Short: "自動掃描並修復安全漏洞",
		Long: `fix 先執行完整安全掃描，然後針對每個發現的問題產生修復建議。

模式：
  sift fix .                掃描 + 顯示修復建議（不套用）
  sift fix . --auto         掃描 + 自動套用所有修復
  sift fix . --interactive  掃描 + 逐一確認後套用`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			// 載入設定
			cfg, _, err := config.Load()
			if err != nil {
				return err
			}

			// Phase 1: 掃描
			fmt.Println("  🔍 Phase 1: 掃描安全漏洞...")
			orch := scan.NewOrchestrator(cfg)
			if err := orch.Run(target, "terminal"); err != nil {
				// 即使掃描有部分錯誤，仍繼續嘗試修復
				fmt.Fprintf(os.Stderr, "  ⚠️  掃描部分失敗: %v\n", err)
			}

			// Phase 2: 取得 findings 並修復
			// 重新掃描取得結構化結果
			fmt.Println()
			fmt.Println("  🔧 Phase 2: 產生修復建議...")
			findings := orch.LastFindings()
			if len(findings) == 0 {
				fmt.Println("  ✅ 沒有需要修復的問題！")
				return nil
			}

			fixer, err := agent.NewFixer(cfg)
			if err != nil {
				return fmt.Errorf("無法初始化修復器: %w", err)
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
					fmt.Printf("\n  ── 修復 [%d/%d] ──\n", i+1, len(results))
					fmt.Printf("  檔案: %s:%d\n", r.Finding.File, r.Finding.Line)
					fmt.Printf("  問題: %s\n", r.Finding.Message)
					fmt.Printf("  修復:\n%s\n", r.Patch)
					fmt.Print("  套用此修復? [y/N/a(ll)/q(uit)]: ")

					var answer string
					fmt.Scanln(&answer)
					switch answer {
					case "q":
						fmt.Println("  已取消。")
						goto done
					case "a":
						interactive = false
						fallthrough
					case "y", "Y":
						if err := fixer.ApplyFix(r); err != nil {
							fmt.Printf("  ❌ 套用失敗: %v\n", err)
						} else {
							fmt.Println("  ✅ 已套用")
							fixedCount++
						}
					default:
						fmt.Println("  ⏭️  跳過")
					}
				} else if auto {
					if err := fixer.ApplyFix(r); err != nil {
						fmt.Printf("  ❌ [%d/%d] 套用失敗: %v\n", i+1, len(results), err)
					} else {
						fmt.Printf("  ✅ [%d/%d] 已修復: %s:%d\n", i+1, len(results), r.Finding.File, r.Finding.Line)
						fixedCount++
					}
				} else {
					fmt.Printf("  📝 [%d/%d] %s:%d\n     %s\n", i+1, len(results), r.Finding.File, r.Finding.Line, truncateLines(r.Patch, 3))
				}
			}

		done:
			fmt.Printf("\n  📊 修復完成: %d/%d 個問題已修復\n", fixedCount, len(results))
			if !dryRun && fixedCount > 0 {
				fmt.Println("  💡 若要還原修復: sift fix --rollback")
				fmt.Println("  💡 重新掃描驗證: sift scan .")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&auto, "auto", false, "自動套用所有修復")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "逐一確認後套用")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "僅顯示修復建議，不套用")

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

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/KJyang-0114/sift/internal/config"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var (
		provider string
		apiKey   string
		model    string
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "執行初次設定精靈",
		Long: `init 會引導你完成初次設定：選擇 LLM Provider、輸入 API Key、以及預設模型。
整個過程最多三個問題，完成後即可開始掃描。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Default()

			if nonInteractive {
				// 非互動模式：從 flag 或環境變數讀取
				if provider != "" {
					cfg.LLM.Provider = config.LLMProvider(provider)
				}
				if apiKey != "" {
					cfg.LLM.APIKey = apiKey
				}
				if model != "" {
					cfg.LLM.Model = model
				}
			} else {
				runWizard(cfg)
			}

			// 寫入設定檔
			path, err := config.Save(cfg)
			if err != nil {
				return fmt.Errorf("無法儲存設定: %w", err)
			}

			fmt.Printf("\n  ✅ 設定已儲存至 %s\n", path)
			fmt.Println("  ✅ 準備就緒！執行: sift scan .")
			return nil
		},
	}

	cmd.Flags().StringVar(&provider, "provider", "", "LLM provider (anthropic|openai|openrouter|ollama)")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "LLM API Key")
	cmd.Flags().StringVar(&model, "model", "", "預設模型")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "非互動模式 (CI/CD 使用)")

	return cmd
}

func runWizard(cfg *config.Config) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("  🔍 Sift Setup Wizard")
	fmt.Println("  ───────────────────────")
	fmt.Println()

	// Q1: Provider
	fmt.Println("  請選擇 LLM Provider:")
	fmt.Println("    [1] Anthropic (Claude)")
	fmt.Println("    [2] OpenAI (GPT-4o)")
	fmt.Println("    [3] OpenRouter (多模型)")
	fmt.Println("    [4] Ollama (本機, 免費)")
	fmt.Println("    [5] 稍後設定 (離線模式, 僅 Semgrep)")
	fmt.Println()
	fmt.Print("  > ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1", "":
		cfg.LLM.Provider = config.ProviderAnthropic
	case "2":
		cfg.LLM.Provider = config.ProviderOpenAI
	case "3":
		cfg.LLM.Provider = config.ProviderOpenRouter
	case "4":
		cfg.LLM.Provider = config.ProviderOllama
	case "5":
		cfg.LLM.Provider = config.ProviderOffline
		fmt.Println("\n  ℹ️  離線模式：僅使用 Semgrep 靜態規則掃描。")
		fmt.Printf("  ✅ 設定已儲存。執行: sift scan .\n")
		return
	}
	fmt.Println()

	if cfg.LLM.Provider != config.ProviderOllama {
		// Q2: API Key
		fmt.Print("  API Key: ")
		apiKey, _ := reader.ReadString('\n')
		cfg.LLM.APIKey = strings.TrimSpace(apiKey)
		fmt.Println()

		// Q3: Model
		defaultModel := cfg.LLM.DefaultModel()
		fmt.Printf("  預設模型 [%s]: ", defaultModel)
		model, _ := reader.ReadString('\n')
		model = strings.TrimSpace(model)
		if model == "" {
			model = defaultModel
		}
		cfg.LLM.Model = model
	}

	if cfg.LLM.Provider == config.ProviderOllama {
		fmt.Print("  Ollama 模型名稱 [llama3]: ")
		model, _ := reader.ReadString('\n')
		model = strings.TrimSpace(model)
		if model == "" {
			model = "llama3"
		}
		cfg.LLM.Model = model
	}
}

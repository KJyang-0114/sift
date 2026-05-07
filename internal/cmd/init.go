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
		Short: "Run the initial setup wizard",
		Long: `init guides you through first-time setup: choose an LLM provider, enter your API key,
	and set the default model. At most three questions — ready to scan when done.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Default()

			if nonInteractive {
				// Non-interactive mode: read from flags or environment variables
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

			// Write config file
			path, err := config.Save(cfg)
			if err != nil {
				return fmt.Errorf("cannot save config: %w", err)
			}

			fmt.Printf("\n  ✅ Config saved to %s\n", path)
			fmt.Println("  ✅ Ready! Run: sift scan .")
			return nil
		},
	}

	cmd.Flags().StringVar(&provider, "provider", "", "LLM provider (anthropic|openai|openrouter|ollama)")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "LLM API Key")
	cmd.Flags().StringVar(&model, "model", "", "default model")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "non-interactive mode (for CI/CD)")

	return cmd
}

func runWizard(cfg *config.Config) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("  🔍 Sift Setup Wizard")
	fmt.Println("  ───────────────────────")
	fmt.Println()

	// Q1: Provider
	fmt.Println("  Select LLM Provider:")
	fmt.Println("    [1] Anthropic (Claude)")
	fmt.Println("    [2] OpenAI (GPT-4o/GPT-5)")
	fmt.Println("    [3] Google Gemini")
	fmt.Println("    [4] OpenRouter (multi-model)")
	fmt.Println("    [5] SiliconFlow (DeepSeek etc.)")
	fmt.Println("    [6] Ollama (local, free)")
	fmt.Println("    [7] Configure later (offline mode, Semgrep only)")
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
		cfg.LLM.Provider = config.ProviderGemini
	case "4":
		cfg.LLM.Provider = config.ProviderOpenRouter
	case "5":
		cfg.LLM.Provider = config.ProviderSiliconFlow
	case "6":
		cfg.LLM.Provider = config.ProviderOllama
	case "7":
		cfg.LLM.Provider = config.ProviderOffline
		fmt.Println("\n  ℹ️  Offline mode: Semgrep static rules only.")
		fmt.Printf("\n  ℹ️  Offline mode: Semgrep static rules only.\n")
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
		fmt.Printf("  Default model [%s]: ", defaultModel)
		model, _ := reader.ReadString('\n')
		model = strings.TrimSpace(model)
		if model == "" {
			model = defaultModel
		}
		cfg.LLM.Model = model
	}

	if cfg.LLM.Provider == config.ProviderOllama {
		fmt.Print("  Ollama model name [llama3]: ")
		model, _ := reader.ReadString('\n')
		model = strings.TrimSpace(model)
		if model == "" {
			model = "llama3"
		}
		cfg.LLM.Model = model
	}
}

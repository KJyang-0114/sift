package config

import "testing"

func TestDefaultReturnsUsableConfiguration(t *testing.T) {
	cfg := Default()
	if cfg.LLM.Provider != ProviderAnthropic {
		t.Fatalf("provider = %q, want %q", cfg.LLM.Provider, ProviderAnthropic)
	}
	if cfg.LLM.Model == "" {
		t.Fatal("default LLM model is empty")
	}
	if cfg.Scan.Timeout <= 0 || cfg.Scan.Concurrency <= 0 {
		t.Fatalf("invalid scan defaults: %#v", cfg.Scan)
	}
	if cfg.Output.Format != "terminal" {
		t.Fatalf("output format = %q, want terminal", cfg.Output.Format)
	}
}

func TestDefaultModelForProvider(t *testing.T) {
	tests := []struct {
		provider LLMProvider
		want     string
	}{
		{ProviderAnthropic, "claude-sonnet-4-6"},
		{ProviderOpenAI, "gpt-4o"},
		{ProviderOpenRouter, "anthropic/claude-sonnet-4.6"},
		{ProviderOllama, "llama3"},
		{ProviderSiliconFlow, "deepseek-ai/DeepSeek-V4-Flash"},
		{ProviderGemini, "gemini-3-flash-preview"},
		{ProviderDeepSeek, "deepseek-chat"},
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			cfg := LLMConfig{Provider: tt.provider}
			if got := cfg.DefaultModel(); got != tt.want {
				t.Fatalf("DefaultModel() = %q, want %q", got, tt.want)
			}
		})
	}
}

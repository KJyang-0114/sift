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

func TestVulnerabilityLookupsDefaultOnAndEnvCanDisable(t *testing.T) {
	if !Default().Vulns.Enabled {
		t.Fatal("vulnerability lookups should be enabled by default")
	}
	for value, want := range map[string]bool{"false": false, "0": false, "OFF": false, "true": true, "": true, "maybe": true} {
		t.Setenv("SIFT_VULNERABILITIES", value)
		cfg := Default()
		cfg.applyEnvOverrides()
		if cfg.Vulns.Enabled != want {
			t.Errorf("SIFT_VULNERABILITIES=%q enabled=%v want %v", value, cfg.Vulns.Enabled, want)
		}
	}
}

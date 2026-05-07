package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// LLMProvider defines supported LLM platforms.
type LLMProvider string

const (
	ProviderAnthropic   LLMProvider = "anthropic"
	ProviderOpenAI      LLMProvider = "openai"
	ProviderOpenRouter  LLMProvider = "openrouter"
	ProviderOllama      LLMProvider = "ollama"
	ProviderSiliconFlow LLMProvider = "siliconflow"
	ProviderGemini      LLMProvider = "gemini"
	ProviderDeepSeek    LLMProvider = "deepseek"
	ProviderOffline     LLMProvider = "offline"
)

// Config is the complete configuration structure for Sift.
type Config struct {
	LLM    LLMConfig    `toml:"llm"`
	Scan   ScanConfig   `toml:"scan"`
	Output OutputConfig `toml:"output"`
}

// LLMConfig defines LLM connection settings.
type LLMConfig struct {
	Provider LLMProvider `toml:"provider"`
	APIKey   string      `toml:"api_key"`
	Model    string      `toml:"model"`
}

// ScanConfig defines scan behavior settings.
type ScanConfig struct {
	Timeout     int    `toml:"timeout"`
	Concurrency int    `toml:"concurrency"`
	Sandbox     string `toml:"sandbox"`
}

// OutputConfig defines output settings.
type OutputConfig struct {
	Format string `toml:"format"`
	Color  bool   `toml:"color"`
}

// Default returns the default configuration.
func Default() *Config {
	return &Config{
		LLM: LLMConfig{
			Provider: ProviderAnthropic,
			Model:    "claude-sonnet-4-6",
		},
		Scan: ScanConfig{
			Timeout:     120,
			Concurrency: 4,
			Sandbox:     "orbital", // The only supported sandbox mode
		},
		Output: OutputConfig{
			Format: "terminal",
			Color:  true,
		},
	}
}

// DefaultModel returns the default model for the given provider.
func (l *LLMConfig) DefaultModel() string {
	switch l.Provider {
	case ProviderAnthropic:
		return "claude-sonnet-4-6"
	case ProviderOpenAI:
		return "gpt-4o"
	case ProviderOpenRouter:
		return "anthropic/claude-sonnet-4.6"
	case ProviderOllama:
		return "llama3"
	case ProviderSiliconFlow:
		return "deepseek-ai/DeepSeek-V4-Flash"
	case ProviderGemini:
		return "gemini-3-flash-preview"
	case ProviderDeepSeek:
		return "deepseek-chat"
	default:
		return "claude-sonnet-4-6"
	}
}

// ConfigDir returns the configuration directory path.
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to get home directory: %w", err)
	}
	return filepath.Join(home, ".sift"), nil
}

// ConfigPath returns the full path to the config file.
func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

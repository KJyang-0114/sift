package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// LLMProvider 定義支援的 LLM 平台。
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

// Config 是 Sift 的完整設定結構。
type Config struct {
	LLM    LLMConfig    `toml:"llm"`
	Scan   ScanConfig   `toml:"scan"`
	Output OutputConfig `toml:"output"`
}

// LLMConfig 定義 LLM 連線設定。
type LLMConfig struct {
	Provider LLMProvider `toml:"provider"`
	APIKey   string      `toml:"api_key"`
	Model    string      `toml:"model"`
}

// ScanConfig 定義掃描行為設定。
type ScanConfig struct {
	Timeout     int    `toml:"timeout"`
	Concurrency int    `toml:"concurrency"`
	Sandbox     string `toml:"sandbox"`
}

// OutputConfig 定義輸出設定。
type OutputConfig struct {
	Format string `toml:"format"`
	Color  bool   `toml:"color"`
}

// Default 回傳預設設定。
func Default() *Config {
	return &Config{
		LLM: LLMConfig{
			Provider: ProviderAnthropic,
			Model:    "claude-sonnet-4-6",
		},
		Scan: ScanConfig{
			Timeout:     120,
			Concurrency: 4,
			Sandbox:     "orbital", // 唯一支援的沙盒模式
		},
		Output: OutputConfig{
			Format: "terminal",
			Color:  true,
		},
	}
}

// DefaultModel 根據 provider 回傳對應的預設模型。
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

// ConfigDir 回傳設定目錄路徑。
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("無法取得使用者目錄: %w", err)
	}
	return filepath.Join(home, ".sift"), nil
}

// ConfigPath 回傳設定檔完整路徑。
func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

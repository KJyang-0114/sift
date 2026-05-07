package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/KJyang-0114/sift/internal/config"
)

// Client is the unified interface for LLM calls.
type Client interface {
	// Chat sends a message and returns the model response.
	Chat(ctx context.Context, systemPrompt, userMessage string) (string, error)

	// Name returns the provider name of this client.
	Name() string
}

// Request represents a standardized LLM request.
type Request struct {
	SystemPrompt string
	UserMessage  string
	MaxTokens    int
	Temperature  float64
}

// Response represents a standardized LLM response.
type Response struct {
	Text      string
	TokensIn  int
	TokensOut int
	Model     string
	Duration  time.Duration
}

// NewClient creates the corresponding LLM client based on configuration.
func NewClient(cfg *config.LLMConfig) (Client, error) {
	switch cfg.Provider {
	case config.ProviderAnthropic:
		return NewAnthropicClient(cfg.APIKey, cfg.Model)
	case config.ProviderOpenAI:
		return NewOpenAIClient(cfg.APIKey, cfg.Model)
	case config.ProviderOpenRouter:
		return NewOpenRouterClient(cfg.APIKey, cfg.Model)
	case config.ProviderOllama:
		return NewOllamaClient(cfg.Model)
	case config.ProviderSiliconFlow:
		return NewSiliconFlowClient(cfg.APIKey, cfg.Model)
	case config.ProviderGemini:
		return NewGeminiClient(cfg.APIKey, cfg.Model)
	case config.ProviderDeepSeek:
		return NewDeepSeekClient(cfg.APIKey, cfg.Model)
	case config.ProviderOffline:
		return nil, fmt.Errorf("LLM not configured (offline mode)")
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", cfg.Provider)
	}
}

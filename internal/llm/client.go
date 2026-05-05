package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/KJyang-0114/sift/internal/config"
)

// Client 是 LLM 調用的統一介面。
type Client interface {
	// Chat 發送訊息並回傳模型回應。
	Chat(ctx context.Context, systemPrompt, userMessage string) (string, error)

	// Name 回傳此 client 的 provider 名稱。
	Name() string
}

// Request 代表一次標準化 LLM 請求。
type Request struct {
	SystemPrompt string
	UserMessage  string
	MaxTokens    int
	Temperature  float64
}

// Response 代表標準化 LLM 回應。
type Response struct {
	Text       string
	TokensIn   int
	TokensOut  int
	Model      string
	Duration   time.Duration
}

// NewClient 根據設定建立對應的 LLM client。
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
	case config.ProviderOffline:
		return nil, fmt.Errorf("LLM 未設定 (離線模式)")
	default:
		return nil, fmt.Errorf("不支援的 LLM provider: %s", cfg.Provider)
	}
}

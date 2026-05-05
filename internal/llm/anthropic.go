package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const anthropicBaseURL = "https://api.anthropic.com/v1/messages"
const anthropicVersion = "2023-06-01"

// AnthropicClient 封裝 Anthropic Messages API。
type AnthropicClient struct {
	apiKey string
	model  string
	client *http.Client
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Model string `json:"model"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NewAnthropicClient 建立 Anthropic API client。
func NewAnthropicClient(apiKey, model string) (*AnthropicClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("Anthropic API key 未設定。請執行 sift init 或設定 SIFT_LLM_API_KEY 環境變數")
	}
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	return &AnthropicClient{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// Name 回傳 provider 名稱。
func (c *AnthropicClient) Name() string {
	return "anthropic"
}

// Chat 向 Anthropic API 發送訊息並取得回應。
func (c *AnthropicClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	req := anthropicRequest{
		Model:       c.model,
		MaxTokens:   4096,
		Temperature: 0.1,
		System:      systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userMessage},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("序列化請求失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", anthropicBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("建立請求失敗: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API 請求失敗: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API 錯誤 (%d): 請確認 API Key 是否正確", resp.StatusCode)
	}

	var result anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析回應失敗: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("Anthropic API 錯誤: %s", result.Error.Message)
	}

	if len(result.Content) == 0 {
		return "", fmt.Errorf("Anthropic 回傳空白回應")
	}

	return result.Content[0].Text, nil
}

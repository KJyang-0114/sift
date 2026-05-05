package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const openRouterBaseURL = "https://openrouter.ai/api/v1/chat/completions"

// OpenRouterClient 封裝 OpenRouter API（相容 OpenAI 格式）。
type OpenRouterClient struct {
	apiKey string
	model  string
	client *http.Client
}

type openRouterChoice struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

type openRouterResponse struct {
	Choices []openRouterChoice `json:"choices"`
	Model   string             `json:"model"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NewOpenRouterClient 建立 OpenRouter API client。
func NewOpenRouterClient(apiKey, model string) (*OpenRouterClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("OpenRouter API key 未設定。請執行 sift init 或設定 SIFT_LLM_API_KEY 環境變數")
	}
	if model == "" {
		model = "anthropic/claude-sonnet-4.6"
	}
	return &OpenRouterClient{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// Name 回傳 provider 名稱。
func (c *OpenRouterClient) Name() string {
	return "openrouter"
}

// Chat 向 OpenRouter API 發送訊息並取得回應。
func (c *OpenRouterClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	messages := []openAIMessage{
		{Role: "user", Content: userMessage},
	}
	if systemPrompt != "" {
		messages = append([]openAIMessage{{Role: "system", Content: systemPrompt}}, messages...)
	}

	req := openAIRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   4096,
		Temperature: 0.1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("序列化請求失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", openRouterBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("建立請求失敗: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("HTTP-Referer", "https://github.com/KJyang-0114/sift")
	httpReq.Header.Set("X-Title", "Sift Code Scanner")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API 請求失敗: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API 錯誤 (%d): 請確認 API Key 是否正確", resp.StatusCode)
	}

	var result openRouterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析回應失敗: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("OpenRouter API 錯誤: %s", result.Error.Message)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("OpenRouter 回傳空白回應")
	}

	return result.Choices[0].Message.Content, nil
}

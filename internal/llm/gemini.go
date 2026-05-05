package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

// GeminiClient 封裝 Google Gemini API（OpenAI 相容格式）。
type GeminiClient struct {
	apiKey string
	model  string
	client *http.Client
}

// NewGeminiClient 建立 Gemini API client。
func NewGeminiClient(apiKey, model string) (*GeminiClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("Gemini API key 未設定")
	}
	if model == "" {
		model = "gemini-3-flash-preview"
	}
	return &GeminiClient{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// Name 回傳 provider 名稱。
func (c *GeminiClient) Name() string {
	return "gemini"
}

// Chat 向 Gemini API 發送訊息並取得回應。
func (c *GeminiClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", geminiBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("建立請求失敗: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API 請求失敗: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Gemini API 錯誤 (%d): 請確認 API Key 是否正確", resp.StatusCode)
	}

	var result openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析回應失敗: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("Gemini API 錯誤: %s", result.Error.Message)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("Gemini 回傳空白回應")
	}

	return result.Choices[0].Message.Content, nil
}

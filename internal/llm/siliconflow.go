package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const siliconFlowBaseURL = "https://api.siliconflow.com/v1/chat/completions"

// SiliconFlowClient 封裝 SiliconFlow API（OpenAI 相容格式，支援 DeepSeek 等模型）。
type SiliconFlowClient struct {
	apiKey string
	model  string
	client *http.Client
}

type siliconFlowRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature float64         `json:"temperature"`
}

// NewSiliconFlowClient 建立 SiliconFlow API client。
func NewSiliconFlowClient(apiKey, model string) (*SiliconFlowClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("SiliconFlow API key 未設定")
	}
	if model == "" {
		model = "deepseek-ai/DeepSeek-V4-Flash"
	}
	return &SiliconFlowClient{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// Name 回傳 provider 名稱。
func (c *SiliconFlowClient) Name() string {
	return "siliconflow"
}

// Chat 向 SiliconFlow API 發送訊息並取得回應。
func (c *SiliconFlowClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	messages := []openAIMessage{
		{Role: "user", Content: userMessage},
	}
	if systemPrompt != "" {
		messages = append([]openAIMessage{{Role: "system", Content: systemPrompt}}, messages...)
	}

	req := siliconFlowRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   4096,
		Temperature: 0.1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("序列化請求失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", siliconFlowBaseURL, bytes.NewReader(body))
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
		return "", fmt.Errorf("SiliconFlow API 錯誤 (%d): 請確認 API Key 和模型名稱是否正確", resp.StatusCode)
	}

	var result openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析回應失敗: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("SiliconFlow API 錯誤: %s", result.Error.Message)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("SiliconFlow 回傳空白回應")
	}

	return result.Choices[0].Message.Content, nil
}

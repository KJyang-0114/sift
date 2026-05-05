package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const openaiBaseURL = "https://api.openai.com/v1/chat/completions"

// OpenAIClient 封裝 OpenAI Chat Completions API。
type OpenAIClient struct {
	apiKey string
	model  string
	client *http.Client
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature float64         `json:"temperature"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Model string `json:"model"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NewOpenAIClient 建立 OpenAI API client。
func NewOpenAIClient(apiKey, model string) (*OpenAIClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("OpenAI API key 未設定。請執行 sift init 或設定 SIFT_LLM_API_KEY 環境變數")
	}
	if model == "" {
		model = "gpt-4o"
	}
	return &OpenAIClient{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// Name 回傳 provider 名稱。
func (c *OpenAIClient) Name() string {
	return "openai"
}

// Chat 向 OpenAI API 發送訊息並取得回應。
func (c *OpenAIClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", openaiBaseURL, bytes.NewReader(body))
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
		return "", fmt.Errorf("API 錯誤 (%d): 請確認 API Key 是否正確", resp.StatusCode)
	}

	var result openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析回應失敗: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("OpenAI API 錯誤: %s", result.Error.Message)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("OpenAI 回傳空白回應")
	}

	return result.Choices[0].Message.Content, nil
}

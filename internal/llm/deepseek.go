package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const deepseekBaseURL = "https://api.deepseek.com/v1/chat/completions"

type DeepSeekClient struct {
	apiKey string
	model  string
	client *http.Client
}

func NewDeepSeekClient(apiKey, model string) (*DeepSeekClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("DeepSeek API key 未設定。請執行 sift init 或設定 SIFT_LLM_API_KEY 環境變數")
	}
	if model == "" {
		model = "deepseek-chat"
	}
	return &DeepSeekClient{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (c *DeepSeekClient) Name() string { return "deepseek" }

func (c *DeepSeekClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type apiReq struct {
		Model       string  `json:"model"`
		Messages    []msg   `json:"messages"`
		MaxTokens   int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
	}
	type apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	messages := []msg{{Role: "user", Content: userMessage}}
	if systemPrompt != "" {
		messages = append([]msg{{Role: "system", Content: systemPrompt}}, messages...)
	}

	body, err := json.Marshal(apiReq{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   4096,
		Temperature: 0.1,
	})
	if err != nil {
		return "", fmt.Errorf("序列化請求失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", deepseekBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("建立請求失敗: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API 請求失敗: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("API 錯誤 (%d): 請確認 API Key 與模型名稱是否正確", httpResp.StatusCode)
	}

	var result apiResp
	if err := json.NewDecoder(httpResp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析回應失敗: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("DeepSeek API 錯誤: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("DeepSeek 回傳空白回應")
	}
	return result.Choices[0].Message.Content, nil
}

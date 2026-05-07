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
		return nil, fmt.Errorf("DeepSeek API key not set. Run sift init or set the SIFT_LLM_API_KEY environment variable")
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
		return "", fmt.Errorf("failed to serialize request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", deepseekBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("API error (%d): please verify your API key and model name are correct", httpResp.StatusCode)
	}

	var result apiResp
	if err := json.NewDecoder(httpResp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("DeepSeek API error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("DeepSeek returned an empty response")
	}
	return result.Choices[0].Message.Content, nil
}

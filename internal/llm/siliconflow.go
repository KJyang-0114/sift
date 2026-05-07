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

// SiliconFlowClient wraps the SiliconFlow API (OpenAI-compatible format, supports DeepSeek and other models).
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

// NewSiliconFlowClient creates a SiliconFlow API client.
func NewSiliconFlowClient(apiKey, model string) (*SiliconFlowClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("SiliconFlow API key not set")
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

// Name returns the provider name.
func (c *SiliconFlowClient) Name() string {
	return "siliconflow"
}

// Chat sends a message to the SiliconFlow API and returns the response.
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
		return "", fmt.Errorf("failed to serialize request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", siliconFlowBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("SiliconFlow API error (%d): please verify your API key and model name are correct", resp.StatusCode)
	}

	var result openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("SiliconFlow API error: %s", result.Error.Message)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("SiliconFlow returned an empty response")
	}

	return result.Choices[0].Message.Content, nil
}

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

// OpenRouterClient wraps the OpenRouter API (OpenAI-compatible format).
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

// NewOpenRouterClient creates an OpenRouter API client.
func NewOpenRouterClient(apiKey, model string) (*OpenRouterClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("OpenRouter API key not set. Run sift init or set the SIFT_LLM_API_KEY environment variable")
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

// Name returns the provider name.
func (c *OpenRouterClient) Name() string {
	return "openrouter"
}

// Chat sends a message to the OpenRouter API and returns the response.
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
		return "", fmt.Errorf("failed to serialize request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", openRouterBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("HTTP-Referer", "https://github.com/KJyang-0114/sift")
	httpReq.Header.Set("X-Title", "Sift Code Scanner")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API error (%d): please verify your API key is correct", resp.StatusCode)
	}

	var result openRouterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("OpenRouter API error: %s", result.Error.Message)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("OpenRouter returned an empty response")
	}

	return result.Choices[0].Message.Content, nil
}

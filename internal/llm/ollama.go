package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const ollamaDefaultURL = "http://localhost:11434/api/generate"

// OllamaClient wraps the Ollama local inference API.
type OllamaClient struct {
	model  string
	client *http.Client
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
	System string `json:"system,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// NewOllamaClient creates an Ollama local client.
func NewOllamaClient(model string) (*OllamaClient, error) {
	if model == "" {
		model = "llama3"
	}
	return &OllamaClient{
		model:  model,
		client: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// Name returns the provider name.
func (c *OllamaClient) Name() string {
	return "ollama"
}

// Chat sends a prompt to the local Ollama instance and returns the response.
func (c *OllamaClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	// Ollama does not natively support system prompt, manually concatenate
	prompt := userMessage
	if systemPrompt != "" {
		prompt = fmt.Sprintf("System: %s\n\nUser: %s", systemPrompt, userMessage)
	}

	req := ollamaRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: false,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to serialize request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ollamaDefaultURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("Ollama connection failed. Please ensure Ollama is running: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Ollama error (%d). Please ensure ollama serve is running and the model is downloaded: ollama pull %s", resp.StatusCode, c.model)
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Response, nil
}

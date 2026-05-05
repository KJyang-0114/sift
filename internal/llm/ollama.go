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

// OllamaClient 封裝 Ollama 本機推論 API。
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

// NewOllamaClient 建立 Ollama 本機 client。
func NewOllamaClient(model string) (*OllamaClient, error) {
	if model == "" {
		model = "llama3"
	}
	return &OllamaClient{
		model:  model,
		client: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// Name 回傳 provider 名稱。
func (c *OllamaClient) Name() string {
	return "ollama"
}

// Chat 向本機 Ollama 發送 prompt 並取得回應。
func (c *OllamaClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	// Ollama 不原生支援 system prompt，手動拼接
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
		return "", fmt.Errorf("序列化請求失敗: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ollamaDefaultURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("建立請求失敗: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("Ollama 連線失敗。請確認 Ollama 已啟動: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Ollama 錯誤 (%d)。請確認 ollama serve 正在執行且已下載模型: ollama pull %s", resp.StatusCode, c.model)
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析回應失敗: %w", err)
	}

	return result.Response, nil
}

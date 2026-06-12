package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ntc/source/application/reports"
)

type OllamaClient struct {
	endpoint string
	client   *http.Client
}

func NewOllamaClient(endpoint string, timeout time.Duration) *OllamaClient {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &OllamaClient{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *OllamaClient) Generate(ctx context.Context, prompt reports.Prompt) (json.RawMessage, error) {
	payload := ollamaChatRequest{
		Model:  prompt.Model,
		Stream: false,
		Format: "json",
		Messages: []ollamaMessage{
			{
				Role:    "system",
				Content: systemPrompt,
			},
			{
				Role:    "user",
				Content: mustJSON(prompt.Input),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("local ai returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}

	return parseAIResponse(data), nil
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Stream   bool            `json:"stream"`
	Format   string          `json:"format,omitempty"`
	Messages []ollamaMessage `json:"messages"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatResponse struct {
	Message ollamaMessage `json:"message"`
}

const systemPrompt = `You analyze local network traffic summaries.
 Return JSON only with keys: summary, risk_level, findings, suspicious_peers, blocked_explanation, recommended_actions. 
 Do not invent facts that are not in the input.`

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func parseAIResponse(data []byte) json.RawMessage {
	var chat ollamaChatResponse
	if err := json.Unmarshal(data, &chat); err == nil && chat.Message.Content != "" {
		content := strings.TrimSpace(chat.Message.Content)
		if json.Valid([]byte(content)) {
			return json.RawMessage(content)
		}
		wrapped, _ := json.Marshal(map[string]string{"summary": content})
		return json.RawMessage(wrapped)
	}

	if json.Valid(data) {
		return json.RawMessage(data)
	}

	wrapped, _ := json.Marshal(map[string]string{"summary": strings.TrimSpace(string(data))})
	return json.RawMessage(wrapped)
}

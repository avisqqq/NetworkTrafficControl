package ai

import (
	"encoding/json"
	"testing"
)

func TestParseAIResponseReadsOllamaMessageJSONContent(t *testing.T) {
	raw := []byte(`{"message":{"role":"assistant","content":"{\"summary\":\"ok\",\"risk_level\":\"low\"}"}}`)

	parsed := parseAIResponse(raw)

	var got map[string]string
	if err := json.Unmarshal(parsed, &got); err != nil {
		t.Fatalf("parsed response is not json: %v", err)
	}
	if got["summary"] != "ok" || got["risk_level"] != "low" {
		t.Fatalf("unexpected parsed response: %#v", got)
	}
}

func TestParseAIResponseWrapsPlainTextOllamaContent(t *testing.T) {
	raw := []byte(`{"message":{"role":"assistant","content":"looks normal"}}`)

	parsed := parseAIResponse(raw)

	var got map[string]string
	if err := json.Unmarshal(parsed, &got); err != nil {
		t.Fatalf("parsed response is not json: %v", err)
	}
	if got["summary"] != "looks normal" {
		t.Fatalf("unexpected summary: %q", got["summary"])
	}
}

func TestParseAIResponseAcceptsPlainJSON(t *testing.T) {
	raw := []byte(`{"summary":"direct"}`)

	parsed := parseAIResponse(raw)

	if string(parsed) != string(raw) {
		t.Fatalf("expected raw JSON to pass through, got %s", parsed)
	}
}

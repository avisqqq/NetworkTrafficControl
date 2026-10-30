package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"ntc/source/domain/policy"
	"ntc/source/infrastructure/http/dto"
)

const policyBody = `{"ip":"203.0.113.10","port":443,"protocol":"tcp","direction":"egress"}`

func policyRequest(t *testing.T, handler http.HandlerFunc, method string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(method, "/policies", strings.NewReader(policyBody))
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func succeed(policy.Rule) error { return nil }

func TestPolicyHandlerPostReturnsNormalizedRule(t *testing.T) {
	handler := PolicyHandler(succeed, succeed, nil)

	recorder := policyRequest(t, handler, http.MethodPost)

	require.Equal(t, http.StatusCreated, recorder.Code)
	var response dto.PolicyResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	require.Equal(t, "TCP", response.Protocol)
	require.Equal(t, "EGRESS", response.Direction)
}

func TestPolicyHandlerMapsErrorsToStatus(t *testing.T) {
	tests := []struct {
		name   string
		method string
		err    error
		want   int
	}{
		{"delete missing rule", http.MethodDelete, policy.ErrRuleNotFound, http.StatusNotFound},
		{"delete wrapped missing rule", http.MethodDelete, fmt.Errorf("map: %w", policy.ErrRuleNotFound), http.StatusNotFound},
		{"add over limit", http.MethodPost, fmt.Errorf("map: %w", policy.ErrRuleLimitReached), http.StatusConflict},
		{"add unknown failure", http.MethodPost, fmt.Errorf("map: broken"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fail := func(policy.Rule) error { return tt.err }
			handler := PolicyHandler(fail, fail, nil)

			recorder := policyRequest(t, handler, tt.method)

			require.Equal(t, tt.want, recorder.Code)
		})
	}
}

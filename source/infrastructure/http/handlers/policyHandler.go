package handlers

import (
	"encoding/json"
	"net/http"

	"ntc/source/domain/packet"
	"ntc/source/domain/policy"
	"ntc/source/infrastructure/http/dto"
)

func PolicyHandler(
	add func(policy.Rule) error,
	remove func(policy.Rule) error,
	getAll func() ([]policy.Rule, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodPost:
			var req dto.PolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			key, err := policyRuleFromRequest(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := add(key); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(dto.PolicyResponse{
				OK:        true,
				IP:        key.IP.ToString(),
				Version:   key.IP.Version,
				Port:      req.Port,
				Protocol:  req.Protocol,
				Direction: req.Direction,
			})

		case http.MethodDelete:
			var req dto.PolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			key, err := policyRuleFromRequest(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := remove(key); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(policyResponse(key))

		case http.MethodGet:
			rules, err := getAll()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			responses := make([]dto.PolicyResponse, 0, len(rules))
			for _, rule := range rules {
				responses = append(responses, policyResponse(rule))
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(responses)

		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func policyResponse(rule policy.Rule) dto.PolicyResponse {
	return dto.PolicyResponse{
		OK:        true,
		IP:        rule.IP.ToString(),
		Version:   rule.IP.Version,
		Port:      rule.Port,
		Protocol:  rule.Protocol.String(),
		Direction: rule.Direction.String(),
	}
}

func policyRuleFromRequest(req dto.PolicyRequest) (policy.Rule, error) {
	ipKey, err := packet.IPKeyFromString(req.IP)
	if err != nil {
		return policy.Rule{}, err
	}
	protocol, err := policy.ProtocolFromString(req.Protocol)
	if err != nil {
		return policy.Rule{}, err
	}
	direction, err := packet.DirectionFromString(req.Direction)
	if err != nil {
		return policy.Rule{}, err
	}
	key, err := policy.NewRule(ipKey, req.Port, protocol, direction)
	if err != nil {
		return policy.Rule{}, err
	}
	return key, nil
}

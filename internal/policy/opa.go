package policy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type OPAPolicy struct {
	serverURL string
	client    *http.Client
}

func NewOPAPolicy(serverURL string) *OPAPolicy {
	return &OPAPolicy{
		serverURL: serverURL,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

// OPARequest represents the input to OPA
type OPARequest struct {
	Input OPAInput `json:"input"`
}

type OPAInput struct {
	APIKey   string `json:"api_key,omitempty"`
	Role     string `json:"role,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Function string `json:"function,omitempty"`
	Action   string `json:"action"` // "get_role", "allow_tool", "allow_function"
}

// OPAResponse represents the unified output from OPA
// OPA can return: {"result": {"allow": true, "role": "admin"}}
type OPAResponse struct {
	Result OPAResult `json:"result"`
}

type OPAResult struct {
	Allow bool   `json:"allow"`
	Role  string `json:"role,omitempty"`
}

func (p *OPAPolicy) query(input OPAInput) OPAResult {
	body, _ := json.Marshal(OPARequest{Input: input})
	resp, err := p.client.Post(p.serverURL, "application/json", bytes.NewReader(body))
	if err != nil {
		slog.Warn("OPA query failed, fail-closed", "err", err)
		return OPAResult{Allow: false}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("OPA returned non-200", "status", resp.StatusCode)
		return OPAResult{Allow: false}
	}

	var out OPAResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		slog.Warn("OPA response decode failed, fail-closed", "err", err)
		return OPAResult{Allow: false}
	}
	return out.Result
}

func (p *OPAPolicy) AllowTool(role, tool string) bool {
	result := p.query(OPAInput{Role: role, Tool: tool, Action: "allow_tool"})
	return result.Allow
}

func (p *OPAPolicy) AllowFunction(role, function string) bool {
	result := p.query(OPAInput{Role: role, Function: function, Action: "allow_function"})
	return result.Allow
}

func (p *OPAPolicy) GetRole(apiKey string) string {
	result := p.query(OPAInput{APIKey: apiKey, Action: "get_role"})
	return result.Role
}

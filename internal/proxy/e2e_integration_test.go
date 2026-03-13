package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secure-mcp-gateway/internal/config"
	"secure-mcp-gateway/internal/policy"
	"secure-mcp-gateway/internal/scanner"
)

func TestE2E_GatewayIntegration(t *testing.T) {
	// 1. Setup Mock Upstream (No Auth)
	publicUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Check for Output DLP scenario
		if strings.Contains(string(body), "fetch_secret") {
			w.Write([]byte(`{"jsonrpc":"2.0", "result":"Here is the key: sk-secretxxxxxxxxxx AWS", "id": 1}`))
			return
		}

		// Normal response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer publicUpstream.Close()

	// 2. Setup Mock Upstream (Bearer Auth Required)
	secureUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer enterprise-super-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"secure-ok","id":1}`))
	}))
	defer secureUpstream.Close()

	// 3. Setup Gateway Configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			RateLimit: config.RateLimitConfig{
				DefaultRPS:   10,
				DefaultBurst: 20,
				RoleOverrides: map[string]config.RateLimitOverride{
					"free-tier": {RPS: 1, Burst: 1}, // Very strict rate limit for testing 429
					"admin":     {RPS: 100, Burst: 200},
				},
			},
		},
		Upstreams: []config.UpstreamConfig{
			{
				ID:       "public",
				BaseURL:  publicUpstream.URL,
				AuthType: config.AuthTypeNone,
			},
			{
				ID:       "secure",
				BaseURL:  secureUpstream.URL,
				AuthType: config.AuthTypeBearer,
				Auth: map[string]interface{}{
					"token": "enterprise-super-token",
				},
			},
		},
	}

	// 4. Setup Policy & Scanner
	polEngine := &policy.LocalPolicy{
		Bindings: map[string]map[string]string{
			"api_keys": {
				"sk-admin": "admin",
				"sk-free":  "free-tier",
			},
		},
		Roles: map[string]policy.Role{
			"admin": {
				AllowTools: []string{"public_ping", "public_fetch_secret", "secure_ping"},
			},
			"free-tier": {
				AllowTools: []string{"public_ping"},
			},
		},
	}

	dlpRulesFilePath := "" // will use defaults (blocks rm -rf, redacts sk-...)
	scanEngine := scanner.NewTokenScannerFromRules(dlpRulesFilePath)

	// 5. Instantiate Proxy
	p := NewProxy(cfg, polEngine, scanEngine, nil)

	// --- Execute E2E Scenarios ---

	t.Run("Scenario A1: Valid API Key & Mapping", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","method":"public_ping","id":1}`
		r := httptest.NewRequest("POST", "/mcp/public", strings.NewReader(reqBody))
		r.Header.Set("X-API-Key", "sk-admin")
		w := httptest.NewRecorder()

		p.HandleRequest(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for admin, got %d", w.Code)
		}
	})

	t.Run("Scenario A2: Invalid Key / Dropped Permission", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","method":"secure_ping","id":1}`
		r := httptest.NewRequest("POST", "/mcp/secure", strings.NewReader(reqBody))
		r.Header.Set("X-API-Key", "sk-free") // Free tier cannot access secure_ping (only public_ping)
		w := httptest.NewRecorder()

		p.HandleRequest(w, r)

		var resp JSONRPCResp
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Error == nil || !strings.Contains(resp.Error.Message, "Permission Denied") {
			t.Errorf("Expected Permission Denied for free-tier calling secure tool, got: %s", w.Body.String())
		}
	})

	t.Run("Scenario A3: Output DLP Redaction", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","method":"public_fetch_secret","id":1}`
		r := httptest.NewRequest("POST", "/mcp/public", strings.NewReader(reqBody))
		r.Header.Set("X-API-Key", "sk-admin")
		w := httptest.NewRecorder()

		p.HandleRequest(w, r)
		respStr := w.Body.String()
		if !strings.Contains(respStr, "[REDACTED]") || strings.Contains(respStr, "sk-secretxxxxxxxxxx") {
			t.Errorf("Expected Output DLP to redact the secret, got: %s", respStr)
		}
	})

	t.Run("Scenario A4: Input DLP Block", func(t *testing.T) {
		// Attempting command injection
		reqBody := `{"jsonrpc":"2.0","method":"public_ping","params":{"cmd":"rm -rf /"},"id":1}`
		r := httptest.NewRequest("POST", "/mcp/public", strings.NewReader(reqBody))
		r.Header.Set("X-API-Key", "sk-admin")
		w := httptest.NewRecorder()

		p.HandleRequest(w, r)

		var resp JSONRPCResp
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Error == nil || !strings.Contains(resp.Error.Message, "Security Block: blocked keyword: rm -rf") {
			t.Errorf("Expected Input DLP Security Block, got: %s", w.Body.String())
		}
	})

	t.Run("Scenario B1: Bearer Token Auth Injection", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","method":"secure_ping","id":1}`
		r := httptest.NewRequest("POST", "/mcp/secure", strings.NewReader(reqBody))
		r.Header.Set("X-API-Key", "sk-admin") // Admin can access secure
		w := httptest.NewRecorder()

		p.HandleRequest(w, r)

		// The upstream mock requires the specific Bearer token injected by the gateway
		if w.Code != http.StatusOK {
			t.Errorf("Expected Gateway to inject Bearer token and get 200 OK, got: %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "secure-ok") {
			t.Errorf("Expected secure response body, got: %s", w.Body.String())
		}
	})

	t.Run("Scenario A5: Role Rate Limits (429)", func(t *testing.T) {
		// The 'free-tier' is limited to 1 RPS, 1 Burst.
		// Send two rapid requests to trip it.

		// Req 1 (Should pass)
		reqBody := `{"jsonrpc":"2.0","method":"public_ping","id":1}`
		r1 := httptest.NewRequest("POST", "/mcp/public", strings.NewReader(reqBody))
		r1.Header.Set("X-API-Key", "sk-free")
		w1 := httptest.NewRecorder()
		p.HandleRequest(w1, r1)

		// Req 2 (Should Fail immediately)
		r2 := httptest.NewRequest("POST", "/mcp/public", strings.NewReader(reqBody))
		r2.Header.Set("X-API-Key", "sk-free")
		w2 := httptest.NewRecorder()
		p.HandleRequest(w2, r2)

		var resp JSONRPCResp
		json.Unmarshal(w2.Body.Bytes(), &resp)
		if resp.Error == nil || resp.Error.Message != "Rate limit exceeded" {
			t.Errorf("Expected Rate limit exceeded for 2nd request, got: %v (w1 was %d)", resp.Error, w1.Code)
		}
	})
}

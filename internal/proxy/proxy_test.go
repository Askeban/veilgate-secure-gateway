package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"secure-mcp-gateway/internal/config"
)

// Mock Policy Engine that allows everything
type MockPolicy struct{}

func (m *MockPolicy) AllowTool(role, tool string) bool         { return true }
func (m *MockPolicy) AllowFunction(role, function string) bool { return true }
func (m *MockPolicy) GetRole(apiKey string) string             { return "admin" }

// Mock Scanner that does nothing
type MockScanner struct{}

func (m *MockScanner) ScanInput(input string) (bool, string) { return true, "" }
func (m *MockScanner) ScanOutput(output string) string       { return output }
func (m *MockScanner) ScanStream(src io.Reader, dst io.Writer) error {
	_, err := io.Copy(dst, src)
	return err
}

func TestProxy_HandleRequest(t *testing.T) {
	// 1. Setup Mock Upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Request
		if r.URL.Path != "/message" {
			t.Errorf("Upstream expected /message, got %s", r.URL.Path)
		}
		// Echo back
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc": "2.0", "result": "pong", "id": 1}`))
	}))
	defer mockUpstream.Close()

	// 2. Setup Proxy
	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "test-upstream", BaseURL: mockUpstream.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// 3. Create Request
	reqBody := `{"jsonrpc": "2.0", "method": "ping", "id": 1}`
	r := httptest.NewRequest("POST", "/mcp/test-upstream", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	// 4. Handle
	p.HandleRequest(w, r)

	// 5. Verify Response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("pong")) {
		t.Errorf("Expected pong response, got %s", string(body))
	}
}

func TestProxy_AggregateTools(t *testing.T) {
	// 1. Setup Mock Upstreams
	u1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"jsonrpc": "2.0",
			"result": {
				"tools": [{"name": "toolA", "inputSchema": {}}]
			},
			"id": 1
		}`))
	}))
	defer u1.Close()

	u2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"jsonrpc": "2.0",
			"result": {
				"tools": [{"name": "toolB", "inputSchema": {}}]
			},
			"id": 1
		}`))
	}))
	defer u2.Close()

	// 2. Setup Proxy
	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "u1", BaseURL: u1.URL},
			{ID: "u2", BaseURL: u2.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// 3. Call Aggregation
	resp := p.AggregateTools(1, "admin")

	// 4. Verify (Naive check since map iteration order is random)
	b, _ := json.Marshal(resp)
	s := string(b)

	if !bytes.Contains(b, []byte("u1_toolA")) {
		t.Errorf("Expected u1_toolA in aggregation, got %s", s)
	}
	if !bytes.Contains(b, []byte("u2_toolB")) {
		t.Errorf("Expected u2_toolB in aggregation, got %s", s)
	}
}

func TestProxy_HandleSSEMessage_Aggregation(t *testing.T) {
	// Test routing of 'tools/call' with namespaced tool name

	// 1. Mock Upstream that expects "realTool"
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		// Check that the name was rewritten
		if !bytes.Contains(b, []byte(`"name":"realTool"`)) {
			t.Errorf("Upstream received wrong body: %s", string(b))
		}
		w.Write([]byte(`{"jsonrpc":"2.0","result":"success","id":1}`))
	}))
	defer mockUpstream.Close()

	// 2. Setup Proxy
	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "u1", BaseURL: mockUpstream.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// Manually inject a session
	ch := make(chan []byte, 10)
	p.sessions.Store("sess1", SessionState{
		Chan:    ch,
		Headers: nil, // Header forwarding not needed for this test format
	})

	// 3. Send Message for "u1_realTool"
	reqBody := `{"jsonrpc":"2.0", "method": "tools/call", "params": {"name": "u1_realTool"}, "id": 1}`
	r := httptest.NewRequest("POST", "/message?sessionId=sess1", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	p.HandleSSEMessage(w, r)

	// 4. Wait for response on channel
	select {
	case msg := <-ch:
		if !bytes.Contains(msg, []byte("success")) {
			t.Errorf("Expected success response on channel, got %s", string(msg))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for SSE response")
	}
}

func TestInjectAuth(t *testing.T) {
	os.Setenv("TEST_TOKEN", "supersecret123")
	defer os.Unsetenv("TEST_TOKEN")

	tests := []struct {
		name            string
		authType        config.AuthType
		authConfig      map[string]interface{}
		originalHeaders http.Header
		expectedHeader  string
		expectedValue   string
	}{
		{
			name:     "Bearer Token with env expansion",
			authType: config.AuthTypeBearer,
			authConfig: map[string]interface{}{
				"token": "${TEST_TOKEN}",
			},
			originalHeaders: nil,
			expectedHeader:  "Authorization",
			expectedValue:   "Bearer supersecret123",
		},
		{
			name:     "API Key with custom header and env expansion",
			authType: config.AuthTypeApiKey,
			authConfig: map[string]interface{}{
				"header": "X-Custom-Key",
				"key":    "${TEST_TOKEN}-suffix",
			},
			originalHeaders: nil,
			expectedHeader:  "X-Custom-Key",
			expectedValue:   "supersecret123-suffix",
		},
		{
			name:     "Forward Header specific header",
			authType: config.AuthTypeForward,
			authConfig: map[string]interface{}{
				"header": "Authorization",
			},
			originalHeaders: http.Header{"Authorization": []string{"Bearer pass-through-token"}},
			expectedHeader:  "Authorization",
			expectedValue:   "Bearer pass-through-token",
		},
		{
			name:            "Forward Header missing original header",
			authType:        config.AuthTypeForward,
			authConfig:      map[string]interface{}{"header": "Authorization"},
			originalHeaders: http.Header{}, // missing
			expectedHeader:  "Authorization",
			expectedValue:   "",
		},
	}

	p := &Proxy{} // Empty proxy just to call the method

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/", nil)
			u := config.UpstreamConfig{
				AuthType: tt.authType,
				Auth:     tt.authConfig,
			}

			p.injectAuth(tt.originalHeaders, req, u)

			val := req.Header.Get(tt.expectedHeader)
			if val != tt.expectedValue {
				t.Errorf("Expected %s: %s, got %s", tt.expectedHeader, tt.expectedValue, val)
			}
		})
	}
}

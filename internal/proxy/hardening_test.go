package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"secure-mcp-gateway/internal/config"
)

// --- Test X-Request-ID Propagation ---

func TestProxy_XRequestID_Generated(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer mockUpstream.Close()

	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "test", BaseURL: mockUpstream.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	reqBody := `{"jsonrpc":"2.0","method":"ping","id":1}`
	r := httptest.NewRequest("POST", "/mcp/test", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	p.HandleRequest(w, r)

	// X-Request-ID should be auto-generated and present in response
	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Error("Expected X-Request-ID header in response, got none")
	}
	if len(rid) < 10 {
		t.Errorf("X-Request-ID looks too short: %s", rid)
	}
}

func TestProxy_XRequestID_Propagated(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer mockUpstream.Close()

	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "test", BaseURL: mockUpstream.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	reqBody := `{"jsonrpc":"2.0","method":"ping","id":1}`
	r := httptest.NewRequest("POST", "/mcp/test", strings.NewReader(reqBody))
	r.Header.Set("X-Request-ID", "my-custom-trace-123")
	w := httptest.NewRecorder()

	p.HandleRequest(w, r)

	// Should echo back the provided X-Request-ID
	rid := w.Header().Get("X-Request-ID")
	if rid != "my-custom-trace-123" {
		t.Errorf("Expected X-Request-ID 'my-custom-trace-123', got '%s'", rid)
	}
}

// --- Test Tool Cache ---

func TestProxy_ToolCache(t *testing.T) {
	callCount := 0
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[{"name":"cachedTool","inputSchema":{}}]},"id":1}`))
	}))
	defer mockUpstream.Close()

	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "cache-test", BaseURL: mockUpstream.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)
	p.toolCacheTTL = 10 * time.Second // Long TTL for test

	// First call: cache miss, should hit upstream
	resp1 := p.AggregateTools(1, "admin")
	b1, _ := json.Marshal(resp1)
	if !bytes.Contains(b1, []byte("cache-test_cachedTool")) {
		t.Errorf("Expected cache-test_cachedTool in first call, got %s", string(b1))
	}
	if callCount != 1 {
		t.Errorf("Expected 1 upstream call, got %d", callCount)
	}

	// Second call: cache hit, should NOT hit upstream
	resp2 := p.AggregateTools(2, "admin")
	b2, _ := json.Marshal(resp2)
	if !bytes.Contains(b2, []byte("cache-test_cachedTool")) {
		t.Errorf("Expected cache-test_cachedTool in cached call, got %s", string(b2))
	}
	if callCount != 1 {
		t.Errorf("Expected still 1 upstream call (cached), got %d", callCount)
	}
}

func TestProxy_ToolCache_Expiry(t *testing.T) {
	callCount := 0
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[{"name":"tool","inputSchema":{}}]},"id":1}`))
	}))
	defer mockUpstream.Close()

	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "exp", BaseURL: mockUpstream.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)
	p.toolCacheTTL = 50 * time.Millisecond // Very short TTL

	// First call
	p.AggregateTools(1, "admin")
	if callCount != 1 {
		t.Fatalf("Expected 1 call, got %d", callCount)
	}

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Second call: cache expired, should hit upstream again
	p.AggregateTools(2, "admin")
	if callCount != 2 {
		t.Errorf("Expected 2 calls after cache expiry, got %d", callCount)
	}
}

// --- Test SSE DLP Scanning ---

func TestProxy_SSE_DLP_Scan(t *testing.T) {
	// Mock upstream returns a response containing a secret
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","result":"key is sk-supersecretkey12345","id":1}`))
	}))
	defer mockUpstream.Close()

	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "dlp", BaseURL: mockUpstream.URL},
		},
	}
	// Use a REAL scanner (not mock) to verify DLP actually works
	sc := &realScanner{}
	p := NewProxy(cfg, &MockPolicy{}, sc, nil)

	ch := make(chan []byte, 10)
	p.sessions.Store("dlp-sess", SessionState{
		Chan:    ch,
		Headers: nil,
	})

	reqBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dlp_readFile"},"id":1}`
	r := httptest.NewRequest("POST", "/message?sessionId=dlp-sess", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	p.HandleSSEMessage(w, r)

	select {
	case msg := <-ch:
		if bytes.Contains(msg, []byte("sk-supersecretkey12345")) {
			t.Error("SECRET LEAKED! DLP did not redact sk- key in SSE response")
		}
		if !bytes.Contains(msg, []byte("[REDACTED]")) {
			t.Errorf("Expected [REDACTED] in response, got: %s", string(msg))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for SSE response")
	}
}

// realScanner is a minimal real scanner for DLP testing
type realScanner struct{}

func (s *realScanner) ScanInput(input string) (bool, string) { return true, "" }
func (s *realScanner) ScanOutput(output string) string {
	// Simple redaction of sk- keys
	import_free_replace := strings.NewReplacer() // We need regexp
	_ = import_free_replace
	// Manual check: for simplicity, if output contains sk- followed by 10+ chars, replace
	result := output
	if idx := strings.Index(result, "sk-"); idx >= 0 {
		end := idx + 3
		for end < len(result) && ((result[end] >= 'a' && result[end] <= 'z') || (result[end] >= 'A' && result[end] <= 'Z') || (result[end] >= '0' && result[end] <= '9')) {
			end++
		}
		if end-idx >= 13 { // sk- + at least 10 chars
			result = result[:idx] + "[REDACTED]" + result[end:]
		}
	}
	return result
}
func (s *realScanner) ScanStream(src io.Reader, dst io.Writer) error {
	_, err := io.Copy(dst, src)
	return err
}

// --- Test Configurable Rate Limits ---

func TestProxy_ConfigurableRateLimits(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer mockUpstream.Close()

	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "rl", BaseURL: mockUpstream.URL},
		},
		Server: config.ServerConfig{
			RateLimit: config.RateLimitConfig{
				DefaultRPS:   1, // 1 request per second
				DefaultBurst: 1, // Burst of 1
			},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// Request 1: should pass
	r1 := httptest.NewRequest("POST", "/mcp/rl", strings.NewReader(`{"jsonrpc":"2.0","method":"ping","id":1}`))
	r1.Header.Set("X-API-Key", "rate-test")
	w1 := httptest.NewRecorder()
	p.HandleRequest(w1, r1)

	body1 := w1.Body.String()
	if strings.Contains(body1, "Rate limit exceeded") {
		t.Error("First request should not be rate limited")
	}

	// Request 2: should be rate limited
	r2 := httptest.NewRequest("POST", "/mcp/rl", strings.NewReader(`{"jsonrpc":"2.0","method":"ping","id":2}`))
	r2.Header.Set("X-API-Key", "rate-test")
	w2 := httptest.NewRecorder()
	p.HandleRequest(w2, r2)

	body2 := w2.Body.String()
	if !strings.Contains(body2, "Rate limit exceeded") {
		t.Errorf("Second request should be rate limited, got: %s", body2)
	}
}

// --- Test Graceful SSE Drain ---

func TestProxy_DrainSSESessions(t *testing.T) {
	cfg := &config.Config{}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// Create a few sessions
	ch1 := make(chan []byte, 10)
	ch2 := make(chan []byte, 10)
	p.sessions.Store("s1", SessionState{Chan: ch1, Headers: nil})
	p.sessions.Store("s2", SessionState{Chan: ch2, Headers: nil})

	// Drain
	p.DrainSSESessions()

	// Both channels should have a shutdown message
	select {
	case msg := <-ch1:
		if !bytes.Contains(msg, []byte("shutting down")) {
			t.Errorf("Expected shutdown message, got: %s", string(msg))
		}
	default:
		t.Error("Channel 1 should have received shutdown message")
	}

	select {
	case msg := <-ch2:
		if !bytes.Contains(msg, []byte("shutting down")) {
			t.Errorf("Expected shutdown message, got: %s", string(msg))
		}
	default:
		t.Error("Channel 2 should have received shutdown message")
	}
}

// --- Test Health Check Endpoint ---

func TestProxy_UpstreamHealth(t *testing.T) {
	cfg := &config.Config{}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// Initially empty
	health := p.GetUpstreamHealth()
	if len(health) != 0 {
		t.Errorf("Expected empty health map, got %v", health)
	}

	// Manually set some health states
	p.upstreamHealth.Store("fs-1", true)
	p.upstreamHealth.Store("fs-2", false)

	health = p.GetUpstreamHealth()
	if !health["fs-1"] {
		t.Error("Expected fs-1 to be healthy")
	}
	if health["fs-2"] {
		t.Error("Expected fs-2 to be unhealthy")
	}
}

// --- Test Config Reload ---

func TestProxy_ReloadConfig(t *testing.T) {
	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "old-upstream", BaseURL: "http://old:9090"},
		},
		Server: config.ServerConfig{
			RateLimit: config.RateLimitConfig{DefaultRPS: 10, DefaultBurst: 20},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	if _, ok := p.upstreams["old-upstream"]; !ok {
		t.Fatal("Expected old-upstream in initial config")
	}

	// Reload with new config
	newCfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "new-upstream", BaseURL: "http://new:9090"},
		},
		Server: config.ServerConfig{
			RateLimit: config.RateLimitConfig{DefaultRPS: 5, DefaultBurst: 10},
		},
	}
	p.ReloadConfig(newCfg)

	if _, ok := p.upstreams["old-upstream"]; ok {
		t.Error("old-upstream should be gone after reload")
	}
	if _, ok := p.upstreams["new-upstream"]; !ok {
		t.Error("new-upstream should be present after reload")
	}
	if p.rateLimitCfg.DefaultRPS != 5 {
		t.Errorf("Expected rate limit RPS=5, got %f", p.rateLimitCfg.DefaultRPS)
	}
}

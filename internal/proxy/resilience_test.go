package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"secure-mcp-gateway/internal/config"

	"github.com/sony/gobreaker"
	"golang.org/x/time/rate"
)

func TestProxy_CircuitBreaker(t *testing.T) {
	// 1. Setup Mock Upstream that always fails with 500
	failCount := 0
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockUpstream.Close()

	// 2. Setup Proxy
	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "cb-test", BaseURL: mockUpstream.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// Overwrite the breaker with a tighter one for testing
	st := gobreaker.Settings{
		Name:        "cb-test",
		MaxRequests: 1,
		Interval:    10 * time.Second,
		Timeout:     10 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			// Trip immediately on 2nd failure
			return counts.Requests >= 2 && counts.TotalFailures >= 2
		},
	}
	p.breakers["cb-test"] = gobreaker.NewCircuitBreaker(st)

	// 3. Fire requests to trip the breaker
	// Req 1: 500
	w := httptest.NewRecorder()
	r1 := httptest.NewRequest("POST", "/mcp/cb-test", strings.NewReader(`{"jsonrpc": "2.0", "method": "ping", "id": 1}`))
	p.HandleRequest(w, r1)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 (JSON-RPC Error), got %d", w.Code)
	}

	// Req 2: 500 -> Should trip
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/mcp/cb-test", strings.NewReader(`{"jsonrpc": "2.0", "method": "ping", "id": 1}`))
	p.HandleRequest(w2, r2)

	// Req 3: Should be Open (Circuit Breaker Error)
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("POST", "/mcp/cb-test", strings.NewReader(`{"jsonrpc": "2.0", "method": "ping", "id": 1}`))
	p.HandleRequest(w3, r3)

	body := w3.Body.String()
	if !strings.Contains(body, "circuit breaker is open") {
		t.Logf("Expected circuit breaker error, got: %s", body)
	}

	// Check failure count - should be 2 (Req 1+2), Req 3 shouldn't reach upstream
	if failCount != 2 {
		t.Errorf("Expected 2 upstream calls, got %d. Breaker didn't open?", failCount)
	}
}

func TestProxy_RateLimiter(t *testing.T) {
	// 1. Setup Mock Upstream (returns OK)
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer mockUpstream.Close()

	// 2. Setup Proxy
	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{ID: "rl-test", BaseURL: mockUpstream.URL},
		},
	}
	p := NewProxy(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// 3. Fire requests with SAME API Key
	apiKey := "spam-bot"
	// 1 req/sec, burst 1
	p.limiters.Store(apiKey, rate.NewLimiter(1, 1))

	// Req 1: Allowed
	r1 := httptest.NewRequest("POST", "/mcp/rl-test", strings.NewReader(`{"jsonrpc": "2.0", "method": "ping", "id": 1}`))
	r1.Header.Set("X-API-Key", apiKey)
	w1 := httptest.NewRecorder()
	p.HandleRequest(w1, r1)
	if w1.Code != http.StatusOK {
		t.Errorf("Req 1 blocked: %d", w1.Code)
	}

	// Req 2: Blocked (Burst exceeded)
	r2 := httptest.NewRequest("POST", "/mcp/rl-test", strings.NewReader(`{"jsonrpc": "2.0", "method": "ping", "id": 1}`))
	r2.Header.Set("X-API-Key", apiKey)
	w2 := httptest.NewRecorder()
	p.HandleRequest(w2, r2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected 200 (JSON RPC Error), got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "Rate limit exceeded") {
		t.Errorf("Req 2 should be rate limited. Got: %s", w2.Body.String())
	}
}

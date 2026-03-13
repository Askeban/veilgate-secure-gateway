package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"secure-mcp-gateway/internal/config"
)

// Mock Policy Engine
type MockPolicy struct{}

func (m *MockPolicy) AllowTool(role, tool string) bool         { return true }
func (m *MockPolicy) AllowFunction(role, function string) bool { return true }
func (m *MockPolicy) GetRole(apiKey string) string             { return "admin" }

// Mock Scanner
type MockScanner struct{}

func (m *MockScanner) ScanInput(input string) (bool, string) { return true, "" }
func (m *MockScanner) ScanOutput(output string) string       { return output }
func (m *MockScanner) ScanStream(src io.Reader, dst io.Writer) error {
	_, err := io.Copy(dst, src)
	return err
}

func TestServer_HealthEndpoint_Healthy(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Addr: ":0",
		},
		Upstreams: []config.UpstreamConfig{
			{ID: "test", BaseURL: "http://localhost:9999"},
		},
	}
	srv := NewServer(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// Mark upstream as healthy
	srv.proxy.SetUpstreamHealth("test", true)

	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "healthy" {
		t.Errorf("Expected 'healthy', got %v", body["status"])
	}
}

func TestServer_HealthEndpoint_Degraded(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Addr: ":0",
		},
		Upstreams: []config.UpstreamConfig{
			{ID: "up1", BaseURL: "http://localhost:9998"},
			{ID: "up2", BaseURL: "http://localhost:9997"},
		},
	}
	srv := NewServer(cfg, &MockPolicy{}, &MockScanner{}, nil)

	// One healthy, one not
	srv.proxy.SetUpstreamHealth("up1", true)
	srv.proxy.SetUpstreamHealth("up2", false)

	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 for degraded, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "degraded" {
		t.Errorf("Expected 'degraded', got %v", body["status"])
	}

	upstreams := body["upstreams"].(map[string]interface{})
	if upstreams["up1"] != true {
		t.Error("Expected up1 to be healthy")
	}
	if upstreams["up2"] != false {
		t.Error("Expected up2 to be unhealthy")
	}
}

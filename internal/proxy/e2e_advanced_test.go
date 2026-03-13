package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"secure-mcp-gateway/internal/config"
	"secure-mcp-gateway/internal/policy"
	"secure-mcp-gateway/internal/scanner"
)

func TestE2E_AdvancedProtocols(t *testing.T) {
	// 1. Setup Mock Upstream (To verify Payload Rewriting)
	var capturedPayload []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPayload, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer upstream.Close()

	// 2. Setup Stdio Adapter Test (Spins up actual cmd/adapter with a dummy bash script)
	// Create a dummy executable script that reads stdin and writes a JSON-RPC response to stdout
	dummyScript := `#!/bin/bash
while IFS= read -r line; do
  printf '{"jsonrpc":"2.0","result":"stdio-success","id":99}\n'
done
`
	err := os.WriteFile("dummy_mcp.sh", []byte(dummyScript), 0755)
	if err != nil {
		t.Fatalf("Failed to create dummy script: %v", err)
	}
	defer os.Remove("dummy_mcp.sh")

	// Compile the adapter
	exec.Command("go", "build", "-o", "adapter.bin", "../../cmd/adapter/main.go").Run()
	defer os.Remove("adapter.bin")

	// Start adapter pointing to dummy script
	adapterCmd := exec.Command("./adapter.bin", "--cmd", "./dummy_mcp.sh", "--addr", ":19090")
	adapterCmd.Start()
	defer adapterCmd.Process.Kill()
	time.Sleep(1 * time.Second) // Wait for adapter to boot

	// 3. Setup Gateway Configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			RateLimit: config.RateLimitConfig{
				DefaultRPS: 100, DefaultBurst: 200,
			},
		},
		Upstreams: []config.UpstreamConfig{
			{ID: "jira", BaseURL: upstream.URL, AuthType: config.AuthTypeNone},
			{ID: "stdio", BaseURL: "http://localhost:19090", AuthType: config.AuthTypeNone},
		},
	}

	polEngine := &policy.LocalPolicy{
		Bindings: map[string]map[string]string{"api_keys": {"sk-admin": "admin"}},
		Roles: map[string]policy.Role{
			"admin": {AllowTools: []string{"jira_createTicket", "stdio_run"}},
		},
	}

	p := NewProxy(cfg, polEngine, scanner.NewTokenScannerFromRules(""), nil)

	// --- Scenarios ---

	t.Run("Scenario C1: Payload Translation (Namespace Rewrite via SSE)", func(t *testing.T) {
		// Create mock SSE session manually
		ch := make(chan []byte, 10)
		p.sessions.Store("test_session_c1", SessionState{
			Chan:    ch,
			Headers: nil,
		})

		// Agent calls "jira_createTicket" via SSE message handler
		reqBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"jira_createTicket","args":{"title":"help"}},"id":1}`
		r := httptest.NewRequest("POST", "/message?sessionId=test_session_c1", strings.NewReader(reqBody))
		r.Header.Set("X-API-Key", "sk-admin")
		w := httptest.NewRecorder()

		p.HandleSSEMessage(w, r)

		if w.Code != http.StatusAccepted {
			t.Fatalf("Expected 202 Accepted, got %d", w.Code)
		}

		// Wait for async processing
		time.Sleep(100 * time.Millisecond)

		var parsedPayload struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		json.Unmarshal(capturedPayload, &parsedPayload)

		if parsedPayload.Params.Name != "createTicket" {
			t.Errorf("Expected Payload translator to strip 'jira_' prefix leaving 'createTicket', but got: %s", parsedPayload.Params.Name)
		}
	})

	t.Run("Scenario C2: Stdio HTTP Adapter Flow", func(t *testing.T) {
		// Call the stdio upstream which maps to our local adapter process executing the bash script
		reqBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"stdio_run"},"id":99}`
		r := httptest.NewRequest("POST", "/mcp/stdio", strings.NewReader(reqBody))
		r.Header.Set("X-API-Key", "sk-admin")
		w := httptest.NewRecorder()

		p.HandleRequest(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK from Stdio Gateway, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "stdio-success") {
			t.Errorf("Expected output from the dummy stdio script, got: %s", w.Body.String())
		}
	})

	t.Run("Scenario C3: SSE Stream Lifecycle", func(t *testing.T) {
		// 1. Connect to SSE
		rConn := httptest.NewRequest("GET", "/sse", nil)
		rConn.Header.Set("X-API-Key", "sk-admin")
		wConn := httptest.NewRecorder()

		// Run SSE handle in background since it blocks keeping connection open
		ctx, cancel := context.WithCancel(context.Background())
		rConn = rConn.WithContext(ctx)
		go p.HandleSSEConn(wConn, rConn)

		time.Sleep(100 * time.Millisecond) // Let stream establish

		// 2. Extract Session ID from 'endpoint' event
		streamOutput := wConn.Body.String()
		if !strings.Contains(streamOutput, "event: endpoint") {
			t.Fatalf("Failed to receive SSE endpoint event")
		}

		// Hacky string split to get session ID
		parts := strings.Split(streamOutput, "sessionId=")
		if len(parts) < 2 {
			t.Fatalf("Could not parse sessionId from output: %s", streamOutput)
		}
		sessionID := strings.Split(parts[1], "\n")[0]

		// 3. Send Message to that Session ID via POST
		reqBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"jira_createTicket"},"id":55}`
		rMsg := httptest.NewRequest("POST", "/message?sessionId="+sessionID, strings.NewReader(reqBody))
		rMsg.Header.Set("X-API-Key", "sk-admin")
		wMsg := httptest.NewRecorder()

		p.HandleSSEMessage(wMsg, rMsg)

		if wMsg.Code != http.StatusAccepted {
			t.Fatalf("Expected 202 Accepted for SSE POST, got %d", wMsg.Code)
		}

		time.Sleep(200 * time.Millisecond) // Wait for async processing
		cancel()                           // Disconnect SSE stream

		// Check the stream output again to see if it received the message result
		finalOutput := wConn.Body.String()
		if !strings.Contains(finalOutput, "event: message") || !strings.Contains(finalOutput, `"id":1`) {
			t.Errorf("Expected SSE stream to receive async JSON-RPC result with echoed ID, got: %s", finalOutput)
		}
	})
}

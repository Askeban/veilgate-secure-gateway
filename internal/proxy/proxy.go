package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"secure-mcp-gateway/internal/audit"
	"secure-mcp-gateway/internal/cache"
	"secure-mcp-gateway/internal/config"
	"secure-mcp-gateway/internal/identity"
	"secure-mcp-gateway/internal/metrics"
	"secure-mcp-gateway/internal/policy"
	"secure-mcp-gateway/internal/scanner"

	"github.com/google/uuid"
	"github.com/sony/gobreaker"
	"golang.org/x/time/rate"
)

type Proxy struct {
	client    *http.Client            // Default client
	clients   map[string]*http.Client // Custom clients per upstream
	upstreams map[string]config.UpstreamConfig
	policy    policy.Engine
	scanner   scanner.StreamInspector // Upgrade interface
	redis     *cache.Client           // Distributed cache
	sessions  sync.Map                // map[string]SessionState (SSE session ID -> state)

	breakers       map[string]*gobreaker.CircuitBreaker
	limiters       sync.Map // map[string]*rate.Limiter (API Key -> Limiter)
	rateLimitCfg   config.RateLimitConfig
	upstreamHealth sync.Map // map[string]bool (upstream ID -> healthy)

	// Tool cache: stores all namespaced tools (unfiltered)
	toolCache     []cachedTool
	toolCacheTime time.Time
	toolCacheMu   sync.RWMutex
	toolCacheTTL  time.Duration // default 5 min
}

type cachedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type SessionState struct {
	Chan    chan []byte
	Headers http.Header
}

func NewProxy(cfg *config.Config, pol policy.Engine, sc scanner.StreamInspector, redisClient *cache.Client) *Proxy {
	// Initialize upstreams map and clients
	// Initialize upstreams map and clients
	upstreams := make(map[string]config.UpstreamConfig)
	clients := make(map[string]*http.Client)
	breakers := make(map[string]*gobreaker.CircuitBreaker)
	defaultClient := &http.Client{Timeout: 30 * time.Second}

	for _, u := range cfg.Upstreams {
		upstreams[u.ID] = u

		// Check for mTLS config
		if u.ClientCertFile != "" || u.CAFile != "" {
			tlsConfig, err := identity.LoadClientTLSConfig(u.ClientCertFile, u.ClientKeyFile, u.CAFile)
			if err != nil {
				slog.Error("Failed to load mTLS for upstream", "upstream", u.ID, "err", err)
				clients[u.ID] = defaultClient
				continue
			}
			clients[u.ID] = &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}
		} else {
			clients[u.ID] = defaultClient
		}

		// Initialize Circuit Breaker per Upstream
		st := gobreaker.Settings{
			Name:        u.ID,
			MaxRequests: 1, // Half-open requests
			Interval:    60 * time.Second,
			Timeout:     30 * time.Second,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
				return counts.Requests >= 5 && failureRatio >= 0.5
			},
		}
		breakers[u.ID] = gobreaker.NewCircuitBreaker(st)
	}

	return &Proxy{
		client:       defaultClient,
		clients:      clients,
		upstreams:    upstreams,
		policy:       pol,
		scanner:      sc,
		breakers:     breakers,
		redis:        redisClient,
		rateLimitCfg: cfg.Server.RateLimit,
		toolCacheTTL: 5 * time.Minute,
	}
}

// ReloadConfig updates proxy internals when config changes (hot-reload)
func (p *Proxy) ReloadConfig(cfg *config.Config) {
	// Update upstreams
	newUpstreams := make(map[string]config.UpstreamConfig)
	for _, u := range cfg.Upstreams {
		newUpstreams[u.ID] = u
	}
	p.upstreams = newUpstreams
	p.rateLimitCfg = cfg.Server.RateLimit
	// Clear limiters so they pick up new config
	p.limiters = sync.Map{}
	slog.Info("Proxy config reloaded", "upstreams", len(newUpstreams))
}

func (p *Proxy) getLimiter(apiKey string, role string) *rate.Limiter {
	rps := p.rateLimitCfg.DefaultRPS
	burst := p.rateLimitCfg.DefaultBurst

	if override, ok := p.rateLimitCfg.RoleOverrides[role]; ok {
		rps = override.RPS
		burst = override.Burst
	}

	if rps <= 0 {
		rps = 10
	}
	if burst <= 0 {
		burst = 20
	}
	limiter, _ := p.limiters.LoadOrStore(apiKey, rate.NewLimiter(rate.Limit(rps), burst))
	return limiter.(*rate.Limiter)
}

// allowRequest determines if an API key is allowed to make a request based on limits.
func (p *Proxy) allowRequest(apiKey string, role string) bool {
	rps := p.rateLimitCfg.DefaultRPS
	if override, ok := p.rateLimitCfg.RoleOverrides[role]; ok {
		rps = override.RPS
	}

	if rps <= 0 {
		rps = 10
	}

	if p.redis != nil && p.redis.Underlying() != nil {
		ctx := context.Background()
		key := fmt.Sprintf("rl:%s", apiKey)

		// Simple Redis rate limiter (sliding window approximation using Exists & Incr)
		count, err := p.redis.Underlying().Incr(ctx, key).Result()
		if err != nil {
			slog.Warn("Redis rate limiting failed, falling back to local memory", "err", err)
			return p.getLimiter(apiKey, role).Allow()
		}

		if count == 1 {
			// First request in the second, set exact expiration
			p.redis.Underlying().Expire(ctx, key, time.Second)
		}

		if count > int64(rps) {
			slog.Debug("Rate limit exceeded via Redis", "key", apiKey, "count", count)
			return false
		}
		return true
	}

	// Local Memory Fallback
	return p.getLimiter(apiKey, role).Allow()
}

// StartHealthChecks begins periodic health checking of all upstreams
func (p *Proxy) StartHealthChecks(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			for id, u := range p.upstreams {
				healthURL := strings.TrimRight(u.BaseURL, "/") + "/healthz"
				client := p.client
				if c, ok := p.clients[id]; ok {
					client = c
				}
				resp, err := client.Get(healthURL)
				healthy := err == nil && resp != nil && resp.StatusCode == http.StatusOK
				if resp != nil {
					resp.Body.Close()
				}
				p.upstreamHealth.Store(id, healthy)
				if !healthy {
					slog.Warn("Upstream health check failed", "upstream", id, "err", err)
				}
			}
		}
	}()
}

// GetUpstreamHealth returns health status of all upstreams
func (p *Proxy) GetUpstreamHealth() map[string]bool {
	status := make(map[string]bool)
	p.upstreamHealth.Range(func(key, value any) bool {
		status[key.(string)] = value.(bool)
		return true
	})
	return status
}

// SetUpstreamHealth sets health status for a specific upstream (used in tests and manual overrides)
func (p *Proxy) SetUpstreamHealth(id string, healthy bool) {
	p.upstreamHealth.Store(id, healthy)
}

// HandleRequest processes an incoming JSON-RPC request
func (p *Proxy) HandleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Identify Upstream based on URL path or header.
	// Convention: /mcp/{upstreamID}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/mcp/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	upstreamID := parts[0]

	upstream, ok := p.upstreams[upstreamID]
	if !ok {
		metrics.HTTPRequestsTotal.WithLabelValues("POST", "404", upstreamID).Inc()
		p.writeRPCError(w, nil, -32004, "Upstream server not found")
		return
	}

	defer func(start time.Time) {
		metrics.HTTPRequestDuration.WithLabelValues("POST", upstreamID).Observe(time.Since(start).Seconds())
	}(time.Now())

	// 2. Read Body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	// Important: restore body for later if needed, but we used bytes for Unmarshal
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Audit Setup
	auditID := uuid.New().String()
	auditRec := &audit.AuditRecord{
		Timestamp:    time.Now(),
		EventID:      auditID,
		UserIdentity: r.RemoteAddr, // Default to IP, enrich with mTLS later if avail
		Action:       "proxy_request",
		InputHash:    audit.ComputeHash(bodyBytes),
		Status:       "pending",
	}
	// Checks for mTLS identity
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		auditRec.UserIdentity = r.TLS.PeerCertificates[0].Subject.CommonName
	}

	var req JSONRPCReq
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		auditRec.Status = "error_json"
		auditRec.Log()
		p.writeRPCError(w, nil, -32700, "Parse error")
		return
	}

	// X-Request-ID: read from header or generate
	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = uuid.New().String()
	}
	auditRec.RequestID = requestID

	// 2.1 Security Checks
	// TODO: Get Role from Header (API Key) correctly
	apiKey := r.Header.Get("X-API-Key")
	role := p.policy.GetRole(apiKey)
	// Rate Limit Check
	if !p.allowRequest(apiKey, role) {
		metrics.RateLimitsExceededTotal.WithLabelValues(role).Inc()
		metrics.HTTPRequestsTotal.WithLabelValues("POST", "429", upstreamID).Inc()
		p.writeRPCError(w, req.ID, -32005, "Rate limit exceeded")
		return
	}

	// Tool Permission Check
	toolName, funcName := splitTool(req.Method)

	// Defer check if method is standard MCP tools/call, because the real tool is inside params.
	if toolName != "tools/call" && toolName != "call_tool" {
		if !p.policy.AllowTool(role, toolName) {
			metrics.PolicyEvaluationsTotal.WithLabelValues("allow_tool", role, "deny").Inc()
			metrics.HTTPRequestsTotal.WithLabelValues("POST", "403", upstreamID).Inc()
			p.writeRPCError(w, req.ID, -32001, "Permission Denied: Tool not allowed")
			return
		}
		metrics.PolicyEvaluationsTotal.WithLabelValues("allow_tool", role, "allow").Inc()
	}

	if funcName != "" && !p.policy.AllowFunction(role, req.Method) {
		metrics.PolicyEvaluationsTotal.WithLabelValues("allow_function", role, "deny").Inc()
		metrics.HTTPRequestsTotal.WithLabelValues("POST", "403", upstreamID).Inc()
		p.writeRPCError(w, req.ID, -32001, "Permission Denied: Function not allowed")
		return
	}
	if funcName != "" {
		metrics.PolicyEvaluationsTotal.WithLabelValues("allow_function", role, "allow").Inc()
	}

	// Policy Check for tools/call (specific audit logging)
	if req.Method == "tools/call" || req.Method == "call_tool" {
		auditRec.Action = "tools/call"
		// Try to extract tool name from Params for audit
		// Simple approach: unmarshal params to map
		var params map[string]interface{}
		_ = json.Unmarshal(req.Params, &params)
		if name, ok := params["name"].(string); ok {
			auditRec.ToolName = name
		}

		if !p.policy.AllowTool(role, auditRec.ToolName) {
			auditRec.Status = "denied_policy"
			auditRec.Log()
			p.writeRPCError(w, req.ID, -32001, "Policy denied tool: "+auditRec.ToolName)
			return
		}
	}

	// Input Scan
	if valid, reason := p.scanner.ScanInput(string(req.Params)); !valid {
		metrics.DLPViolationsTotal.WithLabelValues("input").Inc()
		auditRec.Status = "security_block_input"
		auditRec.Log()
		metrics.HTTPRequestsTotal.WithLabelValues("POST", "403", upstreamID).Inc()
		p.writeRPCError(w, req.ID, -32003, "Security Block: "+reason)
		return
	}

	slog.Debug("Forwarding request", "method", req.Method, "upstream", upstreamID, "role", role)

	// 3. Forward to Upstream
	// We need to capture the response to hash it.
	// We can use a custom writer, but Proxying via p.forward returns *http.Response
	// so we can just read that body.
	startTime := time.Now()
	upstreamResp, err := p.forward(r.Header, upstream, bodyBytes)
	auditRec.Latency = time.Since(startTime).Milliseconds()

	if err != nil {
		metrics.HTTPRequestsTotal.WithLabelValues("POST", "502", upstreamID).Inc()
		auditRec.Status = "error_upstream"
		auditRec.Log()
		p.writeRPCError(w, req.ID, -32002, "Upstream error: "+err.Error())
		return
	}
	defer upstreamResp.Body.Close()

	// Read Response Body for Hashing
	respBodyBytes, readErr := io.ReadAll(upstreamResp.Body)
	if readErr != nil {
		metrics.HTTPRequestsTotal.WithLabelValues("POST", "500", upstreamID).Inc()
		auditRec.Status = "error_read_response"
		auditRec.Log()
		p.writeRPCError(w, req.ID, -32002, "Failed to read upstream response")
		return
	}
	auditRec.OutputHash = audit.ComputeHash(respBodyBytes)

	if upstreamResp.StatusCode != http.StatusOK {
		// Body already read above (respBodyBytes), no need to read again
		slog.Error("Upstream responded with non-200 status", "upstream", upstreamID, "status", upstreamResp.StatusCode, "body", string(respBodyBytes))
		var rpcErrResp JSONRPCResp
		if json.Unmarshal(respBodyBytes, &rpcErrResp) == nil && rpcErrResp.Error != nil {
			p.writeRPCError(w, req.ID, rpcErrResp.Error.Code, rpcErrResp.Error.Message)
		} else {
			p.writeRPCError(w, req.ID, -32002, fmt.Sprintf("Upstream error: status %d, response: %s", upstreamResp.StatusCode, string(respBodyBytes)))
		}
		return
	}

	// 4. Output Scan & Write
	// Since we read the body for hashing, we use ScanOutput (string) instead of ScanStream
	safeBody := p.scanner.ScanOutput(string(respBodyBytes))

	// Audit Redaction Check
	if safeBody != string(respBodyBytes) {
		auditRec.Status = "success_redacted"
		// Optionally update hash to reflect what was actually sent
		auditRec.OutputHash = audit.ComputeHash([]byte(safeBody))
	} else {
		auditRec.Status = "success"
	}
	auditRec.Log()

	// Write Response headers
	for k, vv := range upstreamResp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Request-ID", requestID)
	w.WriteHeader(upstreamResp.StatusCode)
	w.Write([]byte(safeBody))

	metrics.HTTPRequestsTotal.WithLabelValues("POST", fmt.Sprintf("%d", upstreamResp.StatusCode), upstreamID).Inc()
}

func splitTool(method string) (string, string) {
	parts := strings.Split(method, ".")
	if len(parts) > 0 {
		return parts[0], method
	}
	return method, ""
}

func (p *Proxy) forward(originalHeaders http.Header, u config.UpstreamConfig, body []byte) (*http.Response, error) {
	// Construct Upstream URL
	// If base_url ends with /, trim it.
	targetURL := strings.TrimRight(u.BaseURL, "/") + "/message" // Using /message as standard per Adapter

	upReq, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	upReq.Header.Set("Content-Type", "application/json")

	// Inject Credentials
	p.injectAuth(originalHeaders, upReq, u)

	// Select client
	client := p.client
	if c, ok := p.clients[u.ID]; ok {
		client = c
	}

	// Execute via Circuit Breaker
	var resp *http.Response
	cb, ok := p.breakers[u.ID]
	if !ok {
		// Fallback if no breaker found (shouldn't happen given constructor)
		return client.Do(upReq)
	}

	_, cbErr := cb.Execute(func() (interface{}, error) {
		var err error
		resp, err = client.Do(upReq)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 500 {
			// Count 5xx as failures for CB
			return nil, fmt.Errorf("upstream 5xx: %d", resp.StatusCode)
		}
		return nil, nil
	})

	if cbErr != nil {
		if strings.Contains(cbErr.Error(), "circuit breaker is open") {
			metrics.CircuitBreakerTripsTotal.WithLabelValues(u.ID).Inc()
		}
		// If we got a response (e.g. 500), we want to return it despite the CB error
		if resp != nil {
			return resp, nil
		}
		// Otherwise (network error or CB open), return the error
		return nil, cbErr
	}

	return resp, nil
}

func (p *Proxy) injectAuth(originalHeaders http.Header, req *http.Request, u config.UpstreamConfig) {
	switch u.AuthType {
	case config.AuthTypeApiKey:
		if key, ok := u.Auth["key"].(string); ok {
			header := "Authorization"
			if h, exists := u.Auth["header"].(string); exists {
				header = h
			}
			req.Header.Set(header, os.ExpandEnv(key)) // Simplest case, or Bearer ...
		}
	case config.AuthTypeBearer:
		if token, ok := u.Auth["token"].(string); ok {
			req.Header.Set("Authorization", "Bearer "+os.ExpandEnv(token))
		}
	case config.AuthTypeForward:
		// Forward the Authorization header from the original client request
		if originalHeaders != nil {
			headerToForward := "Authorization"
			if h, exists := u.Auth["header"].(string); exists {
				headerToForward = h
			}
			if val := originalHeaders.Get(headerToForward); val != "" {
				req.Header.Set(headerToForward, val)
			}
		}
	}
	// TODO: Add mTLS support in client creation, not here
}

func (p *Proxy) writeRPCError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResp{
		JSONRPC: "2.0",
		Error:   &RPCError{Code: code, Message: msg},
		ID:      id,
	})
}

// HandleSSEConn establishes an SSE connection with the client
func (p *Proxy) HandleSSEConn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	sessionID := uuid.New().String()
	msgChan := make(chan []byte, 100)
	p.sessions.Store(sessionID, SessionState{
		Chan:    msgChan,
		Headers: r.Header.Clone(), // Capture headers for AuthTypeForward
	})
	defer p.sessions.Delete(sessionID)

	// Send Endpoint Event
	// The client will use this endpoint to send POST messages
	// Format: /message?sessionId=<sessionID>
	endpoint := fmt.Sprintf("/message?sessionId=%s", sessionID)
	// Some clients expect specific format, generic MCP one:
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpoint)
	w.(http.Flusher).Flush()

	slog.Info("SSE Client connected", "session", sessionID)
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	// Keep connection open
	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			slog.Info("SSE Client disconnected", "session", sessionID)
			return
		case msg := <-msgChan:
			// Write message as 'message' event
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(msg))
			w.(http.Flusher).Flush()
		}
	}
}

// HandleSSEMessage handles incoming JSON-RPC messages for an SSE session
func (p *Proxy) HandleSSEMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate Limit Check (SSE Message)
	apiKey := r.Header.Get("X-API-Key")
	role := p.policy.GetRole(apiKey)
	if !p.allowRequest(apiKey, role) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	v, ok := p.sessions.Load(sessionID)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}
	sessionState := v.(SessionState)
	msgChan := sessionState.Chan
	originalHeaders := sessionState.Headers

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// 202 Accepted - processing async
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("Accepted"))

	go func() {
		// Audit Setup
		auditRec := &audit.AuditRecord{
			Timestamp:    time.Now(),
			EventID:      uuid.New().String(),
			UserIdentity: r.RemoteAddr,
			Action:       "sse_request",
			InputHash:    audit.ComputeHash(body),
			Status:       "pending",
		}

		var req JSONRPCReq
		if err := json.Unmarshal(body, &req); err != nil {
			auditRec.Status = "error_json"
			auditRec.Log()
			p.sendError(msgChan, nil, -32700, "Parse error")
			return
		}

		// 1. Handle tools/list (Aggregation)
		if req.Method == "tools/list" {
			auditRec.Action = "tools/list"
			auditRec.Status = "success"
			auditRec.Log()

			apiKey := r.Header.Get("X-API-Key")
			role := p.policy.GetRole(apiKey)

			resp := p.AggregateTools(req.ID, role)
			b, _ := json.Marshal(resp)
			msgChan <- b
			return
		}

		// 2. Handle tools/call (Routing)
		if req.Method == "tools/call" || req.Method == "call_tool" {
			auditRec.Action = "tools/call"
			var params struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(req.Params, &params); err != nil {
				auditRec.Status = "error_params"
				auditRec.Log()
				p.sendError(msgChan, req.ID, -32602, "Invalid params")
				return
			}
			auditRec.ToolName = params.Name

			// Split upstream_tool
			parts := strings.SplitN(params.Name, "_", 2)
			if len(parts) < 2 {
				auditRec.Status = "error_namespace"
				auditRec.Log()
				// Fallback: try to find upstream that has this tool? Too slow.
				// Fail if not namespaced
				p.sendError(msgChan, req.ID, -32602, "Tool name must be namespaced (upstreamID_toolName)")
				return
			}
			upstreamID := parts[0]
			realToolName := parts[1]

			upstream, ok := p.upstreams[upstreamID]
			if !ok {
				p.sendError(msgChan, req.ID, -32004, "Upstream not found: "+upstreamID)
				return
			}

			// Rewrite request Params to use real tool name
			// This is tricky with raw JSON. We need to decode, modify, encode.
			var fullParams map[string]interface{}
			_ = json.Unmarshal(req.Params, &fullParams) // already checked valid json above
			fullParams["name"] = realToolName
			newParams, _ := json.Marshal(fullParams)

			req.Params = json.RawMessage(newParams)
			newBody, _ := json.Marshal(req)

			// Forward using the original SSE connection headers
			resp, err := p.forward(originalHeaders, upstream, newBody)
			if err != nil {
				p.sendError(msgChan, req.ID, -32002, "Upstream error: "+err.Error())
				return
			}
			defer resp.Body.Close()

			respBytes, _ := io.ReadAll(resp.Body)
			// DLP: Scan output before sending to client
			safeResp := p.scanner.ScanOutput(string(respBytes))
			msgChan <- []byte(safeResp)
			return
		}

		// Default: Unknown or unsupported method in Aggregation mode
		p.sendError(msgChan, req.ID, -32601, "Method not supported in aggregated mode: "+req.Method)
	}()
}

func (p *Proxy) sendError(ch chan []byte, id any, code int, msg string) {
	resp := JSONRPCResp{
		JSONRPC: "2.0",
		Error:   &RPCError{Code: code, Message: msg},
		ID:      id,
	}
	b, _ := json.Marshal(resp)
	ch <- b
}

// DrainSSESessions gracefully notifies all SSE clients before shutdown
func (p *Proxy) DrainSSESessions() {
	p.sessions.Range(func(key, value any) bool {
		state := value.(SessionState)
		ch := state.Chan
		// Send a close notification
		closeMsg := JSONRPCResp{
			JSONRPC: "2.0",
			Error:   &RPCError{Code: -32000, Message: "Server shutting down"},
		}
		b, _ := json.Marshal(closeMsg)
		select {
		case ch <- b:
		default:
			// Channel full or closed, skip
		}
		return true
	})
	slog.Info("SSE sessions drained")
}

func (p *Proxy) AggregateTools(id any, role string) JSONRPCResp {
	type ToolsListResult struct {
		Tools []cachedTool `json:"tools"`
	}
	type ToolsListResp struct {
		Result ToolsListResult `json:"result"`
		Error  *RPCError       `json:"error,omitempty"`
	}

	// Check cache first (Redis then memory)
	var cachedTools []cachedTool
	cacheValid := false

	ctx := context.Background()
	cacheKey := "tools:aggregated"

	if p.redis != nil && p.redis.Underlying() != nil {
		if val, err := p.redis.Underlying().Get(ctx, cacheKey).Result(); err == nil {
			if json.Unmarshal([]byte(val), &cachedTools) == nil {
				cacheValid = true
				slog.Debug("Tool cache hit (Redis)")
			}
		}
	} else {
		// Local memory fallback
		p.toolCacheMu.RLock()
		cacheValid = len(p.toolCache) > 0 && time.Since(p.toolCacheTime) < p.toolCacheTTL
		if cacheValid {
			cachedTools = make([]cachedTool, len(p.toolCache))
			copy(cachedTools, p.toolCache)
			slog.Debug("Tool cache hit (Memory)")
		}
		p.toolCacheMu.RUnlock()
	}

	if cacheValid {
		metrics.CacheHitsTotal.Inc()
	}

	if !cacheValid {
		metrics.CacheMissesTotal.Inc()
		// Cache miss: scatter-gather from all upstreams
		var allTools []cachedTool
		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, u := range p.upstreams {
			wg.Add(1)
			go func(u config.UpstreamConfig) {
				defer wg.Done()
				req := JSONRPCReq{
					JSONRPC: "2.0",
					Method:  "tools/list",
					ID:      1,
				}
				body, _ := json.Marshal(req)
				// For tool aggregation, we don't have original headers per upstream
				// If AuthTypeForward is used, it will be blank, simulating a service account call.
				var emptyHeaders http.Header
				resp, err := p.forward(emptyHeaders, u, body)
				if err != nil {
					slog.Warn("Failed to list tools from upstream", "upstream", u.ID, "err", err)
					return
				}
				defer resp.Body.Close()

				b, _ := io.ReadAll(resp.Body)
				var r ToolsListResp
				if err := json.Unmarshal(b, &r); err == nil && r.Error == nil {
					mu.Lock()
					for _, t := range r.Result.Tools {
						namespacedName := fmt.Sprintf("%s_%s", u.ID, t.Name)
						t.Name = namespacedName
						allTools = append(allTools, t)
					}
					mu.Unlock()
				}
			}(u)
		}
		wg.Wait()

		// Store in cache (all tools, unfiltered)
		if p.redis != nil && p.redis.Underlying() != nil {
			if b, err := json.Marshal(allTools); err == nil {
				p.redis.Underlying().Set(ctx, cacheKey, string(b), p.toolCacheTTL)
			}
		} else {
			p.toolCacheMu.Lock()
			p.toolCache = allTools
			p.toolCacheTime = time.Now()
			p.toolCacheMu.Unlock()
		}

		cachedTools = allTools
		slog.Debug("Tool cache refreshed", "count", len(allTools))
	}

	// Filter by role (always per-request)
	var filtered []cachedTool
	for _, t := range cachedTools {
		if p.policy.AllowTool(role, t.Name) {
			filtered = append(filtered, t)
		}
	}

	return JSONRPCResp{
		JSONRPC: "2.0",
		Result: func() json.RawMessage {
			b, _ := json.Marshal(ToolsListResult{Tools: filtered})
			return json.RawMessage(b)
		}(),
		ID: id,
	}
}

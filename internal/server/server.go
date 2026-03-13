package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"log/slog"
	"secure-mcp-gateway/internal/cache"
	"secure-mcp-gateway/internal/config"
	"secure-mcp-gateway/internal/identity"
	"secure-mcp-gateway/internal/policy"
	"secure-mcp-gateway/internal/proxy"
	"secure-mcp-gateway/internal/scanner"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	cfg    *config.Config
	router *http.ServeMux
	proxy  *proxy.Proxy
}

func NewServer(cfg *config.Config, pol policy.Engine, sc scanner.StreamInspector, redisClient *cache.Client) *Server {
	mux := http.NewServeMux()
	p := proxy.NewProxy(cfg, pol, sc, redisClient)
	s := &Server{
		cfg:    cfg,
		router: mux,
		proxy:  p,
	}
	s.routes()

	// Start upstream health checks (every 30s)
	p.StartHealthChecks(30 * time.Second)

	return s
}

// GetProxy returns the proxy instance (for config reload wiring)
func (s *Server) GetProxy() *proxy.Proxy {
	return s.proxy
}

func (s *Server) routes() {
	// Basic health check
	s.router.HandleFunc("GET /healthz", s.healthHandler)

	// Metrics endpoint for Prometheus scraper
	s.router.Handle("GET /metrics", promhttp.Handler())

	// Register MCP Proxy Route
	s.router.HandleFunc("/mcp/", s.proxy.HandleRequest)

	// Register SSE Routes if enabled
	if s.cfg.Server.SSEEnabled {
		slog.Info("Enabling SSE Routes")
		s.router.HandleFunc("GET /sse", s.proxy.HandleSSEConn)
		s.router.HandleFunc("POST /message", s.proxy.HandleSSEMessage)
	}
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	upstreamHealth := s.proxy.GetUpstreamHealth()

	type HealthResponse struct {
		Status    string          `json:"status"`
		Upstreams map[string]bool `json:"upstreams,omitempty"`
	}

	overall := "healthy"
	for _, healthy := range upstreamHealth {
		if !healthy {
			overall = "degraded"
			break
		}
	}

	resp := HealthResponse{
		Status:    overall,
		Upstreams: upstreamHealth,
	}

	w.Header().Set("Content-Type", "application/json")
	if overall != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) Start() error {
	srv := &http.Server{
		Addr:    s.cfg.Server.Addr,
		Handler: s.router,
	}

	if s.cfg.Server.MTLS {
		tlsConfig, err := identity.LoadServerTLSConfig(
			s.cfg.Server.CertFile,
			s.cfg.Server.KeyFile,
			s.cfg.Server.CAFile,
		)
		if err != nil {
			return err
		}
		srv.TLSConfig = tlsConfig
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		var err error
		if s.cfg.Server.MTLS {
			slog.Info("Starting HTTPS server (mTLS enabled)", "addr", s.cfg.Server.Addr)
			err = srv.ListenAndServeTLS("", "")
		} else {
			slog.Info("Starting HTTP server", "addr", s.cfg.Server.Addr)
			err = srv.ListenAndServe()
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server start failed", "error", err)
			close(done)
		}
	}()

	slog.Info("Server listening", "addr", s.cfg.Server.Addr)
	<-done
	slog.Info("Server stopping...")

	// Graceful SSE drain: notify connected SSE clients
	s.proxy.DrainSSESessions()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return err
	}
	slog.Info("Server exited properly")
	return nil
}

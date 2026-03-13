package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// --- HTTP & Traffic Metrics ---
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcp_gateway_http_requests_total",
			Help: "Total number of HTTP requests processed by the gateway",
		},
		[]string{"method", "status", "upstream"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mcp_gateway_http_request_duration_seconds",
			Help:    "Histogram of response latency (seconds)",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "upstream"},
	)

	ActiveConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "mcp_gateway_active_connections",
			Help: "Current number of active server connections (HTTP & SSE)",
		},
	)

	// --- Security & Resiliency Metrics ---
	PolicyEvaluationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcp_gateway_policy_evaluations_total",
			Help: "Total number of authorization evaluations",
		},
		[]string{"action", "role", "result"}, // result: allow/deny
	)

	RateLimitsExceededTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcp_gateway_rate_limits_exceeded_total",
			Help: "Total number of requests rejected due to rate limiting",
		},
		[]string{"role"},
	)

	CircuitBreakerTripsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcp_gateway_circuit_breaker_trips_total",
			Help: "Total number of times a circuit breaker opened",
		},
		[]string{"upstream"},
	)

	// --- DLP & Scanner Metrics ---
	DLPScansTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mcp_gateway_dlp_scans_total",
			Help: "Total number of streams passed through the DLP engine",
		},
	)

	DLPViolationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcp_gateway_dlp_violations_total",
			Help: "Total number of input requests blocked by the DLP scanner",
		},
		[]string{"pattern"},
	)

	DLPRedactionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcp_gateway_dlp_redactions_total",
			Help: "Total number of output streams redacted and sanitized",
		},
		[]string{"pattern"},
	)

	// --- Cache Metrics ---
	CacheHitsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mcp_gateway_cache_hits_total",
			Help: "Total number of successful tool cache retrievals",
		},
	)

	CacheMissesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mcp_gateway_cache_misses_total",
			Help: "Total number of cache misses requiring upstream aggregation",
		},
	)
)

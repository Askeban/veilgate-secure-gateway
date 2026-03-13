package config

import (
	"log/slog"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig     `mapstructure:"server"`
	Log       LogConfig        `mapstructure:"log"`
	Upstreams []UpstreamConfig `mapstructure:"upstreams"`
}

type ServerConfig struct {
	Addr     string `mapstructure:"addr"`      // e.g., ":8080"
	MTLS     bool   `mapstructure:"mtls"`      // Enable mTLS
	CertFile string `mapstructure:"cert_file"` // Path to server cert
	KeyFile  string `mapstructure:"key_file"`  // Path to server key
	CAFile   string `mapstructure:"ca_file"`   // Path to CA for client verification

	// Policy Config
	PolicyType string    `mapstructure:"policy_type"` // "local" or "opa"
	PolicyPath string    `mapstructure:"policy_path"` // for local json
	OPA        OPAConfig `mapstructure:"opa"`         // for opa config

	// Protocol Features
	SSEEnabled         bool `mapstructure:"sse_enabled"`
	AggregationEnabled bool `mapstructure:"aggregation_enabled"`

	// DLP
	DLPRulesPath string `mapstructure:"dlp_rules_path"` // Path to dlp_rules.json

	// Audit
	Audit AuditConfig `mapstructure:"audit"`

	// Rate Limiting
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`

	// Distributed State (Redis)
	Redis RedisConfig `mapstructure:"redis"`
}

type OPAConfig struct {
	ServerURL string `mapstructure:"server_url"`
}

type RedisConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Addr     string `mapstructure:"addr"`     // e.g. "localhost:6379"
	Password string `mapstructure:"password"` // "" for no password
	DB       int    `mapstructure:"db"`       // default 0
}

type AuditConfig struct {
	FilePath string `mapstructure:"file_path"` // e.g., "/var/log/mcp-audit.jsonl"
}

type RateLimitConfig struct {
	DefaultRPS    float64                      `mapstructure:"default_rps"`   // Default requests per second
	DefaultBurst  int                          `mapstructure:"default_burst"` // Default burst size
	RoleOverrides map[string]RateLimitOverride `mapstructure:"role_overrides"`
}

type RateLimitOverride struct {
	RPS   float64 `mapstructure:"rps"`
	Burst int     `mapstructure:"burst"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`  // debug, info, warn, error
	Format string `mapstructure:"format"` // json, text
}

type AuthType string

const (
	AuthTypeNone    AuthType = "none"
	AuthTypeApiKey  AuthType = "api-key"
	AuthTypeBearer  AuthType = "bearer"
	AuthTypeBasic   AuthType = "basic"
	AuthTypeMTLS    AuthType = "mtls"
	AuthTypeForward AuthType = "forward"
)

type UpstreamConfig struct {
	ID       string                 `mapstructure:"id"`
	BaseURL  string                 `mapstructure:"base_url"`
	AuthType AuthType               `mapstructure:"auth_type"`
	Auth     map[string]interface{} `mapstructure:"auth"` // Flexible auth config
	// mTLS for Upstream
	ClientCertFile string `mapstructure:"client_cert_file"`
	ClientKeyFile  string `mapstructure:"client_key_file"`
	CAFile         string `mapstructure:"ca_file"`
}

func LoadConfig(path string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("server.sse_enabled", false)
	v.SetDefault("server.aggregation_enabled", false)
	v.SetDefault("server.dlp_rules_path", "dlp_rules.json")
	v.SetDefault("server.rate_limit.default_rps", 10)
	v.SetDefault("server.rate_limit.default_burst", 20)
	v.SetDefault("server.redis.enabled", false)
	v.SetDefault("server.redis.addr", "localhost:6379")
	v.SetDefault("server.redis.db", 0)

	// Env vars: SMG_SERVER_ADDR -> server.addr
	v.SetEnvPrefix("SMG")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.AddConfigPath(".")
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// WatchConfig watches the config file for changes and calls the callback with the new config.
// This enables hot-reload when used with Kubernetes ConfigMap mounts or local file edits.
func WatchConfig(path string, callback func(*Config)) {
	v := viper.New()

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.AddConfigPath(".")
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	v.SetDefault("server.addr", ":8080")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("server.sse_enabled", false)
	v.SetDefault("server.aggregation_enabled", false)
	v.SetDefault("server.dlp_rules_path", "dlp_rules.json")
	v.SetDefault("server.rate_limit.default_rps", 10)
	v.SetDefault("server.rate_limit.default_burst", 20)
	v.SetDefault("server.redis.enabled", false)
	v.SetDefault("server.redis.addr", "localhost:6379")
	v.SetDefault("server.redis.db", 0)

	if err := v.ReadInConfig(); err != nil {
		slog.Warn("Config watch: failed to read initial config", "err", err)
		return
	}

	v.OnConfigChange(func(e fsnotify.Event) {
		slog.Info("Config file changed, reloading", "file", e.Name)
		var cfg Config
		if err := v.Unmarshal(&cfg); err != nil {
			slog.Error("Config reload failed to unmarshal", "err", err)
			return
		}
		callback(&cfg)
	})
	v.WatchConfig()
	slog.Info("Config file watch enabled", "path", v.ConfigFileUsed())
}

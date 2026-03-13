package cache

import (
	"context"
	"log/slog"

	"secure-mcp-gateway/internal/config"

	"github.com/redis/go-redis/v9"
)

// Client wraps the Redis client
type Client struct {
	rdb *redis.Client
}

// NewClient initializes a new Redis client based on config
func NewClient(cfg config.RedisConfig) *Client {
	if !cfg.Enabled {
		return nil // Return nil if Redis is explicitly disabled
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password, // no password set
		DB:       cfg.DB,       // use default DB
	})

	// Ping to verify connection immediately during startup
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		slog.Error("Failed to connect to Redis", "addr", cfg.Addr, "err", err)
		return nil
	}

	slog.Info("Connected to Redis", "addr", cfg.Addr, "db", cfg.DB)
	return &Client{rdb: rdb}
}

// Underlying returns the original go-redis client.
func (c *Client) Underlying() *redis.Client {
	if c == nil {
		return nil
	}
	return c.rdb
}

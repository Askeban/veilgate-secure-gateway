package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"
)

// AuditRecord defines the schema for analytics/security logs
type AuditRecord struct {
	Timestamp    time.Time `json:"timestamp"`
	EventID      string    `json:"event_id"`
	RequestID    string    `json:"request_id,omitempty"`
	UserIdentity string    `json:"user_identity"`
	Action       string    `json:"action"`
	ToolName     string    `json:"tool_name,omitempty"`
	InputHash    string    `json:"input_hash"`
	OutputHash   string    `json:"output_hash"`
	Status       string    `json:"status"`
	Latency      int64     `json:"latency_ms"`
}

// ComputeHash returns SHA-256 hex string of data
func ComputeHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// AuditLogger manages audit output destinations
type AuditLogger struct {
	file *os.File
	mu   sync.Mutex
}

var defaultLogger *AuditLogger

// InitAuditFile opens an audit log file for appending.
// If filePath is empty, audit records are only written to slog (stdout).
func InitAuditFile(filePath string) {
	if filePath == "" {
		return
	}
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error("Failed to open audit file, audit will only go to stdout", "path", filePath, "err", err)
		return
	}
	defaultLogger = &AuditLogger{file: f}
	slog.Info("Audit file logging enabled", "path", filePath)
}

// Log writes the audit record to slog AND to the audit file (if configured)
func (a *AuditRecord) Log() {
	b, _ := json.Marshal(a)
	record := string(b)

	// Always log to slog (stdout)
	slog.Info("AUDIT_RECORD", "record", record)

	// Also write to file if configured
	if defaultLogger != nil && defaultLogger.file != nil {
		defaultLogger.mu.Lock()
		defer defaultLogger.mu.Unlock()
		defaultLogger.file.Write(append(b, '\n'))
	}
}

// CloseAuditFile closes the audit log file handle
func CloseAuditFile() {
	if defaultLogger != nil && defaultLogger.file != nil {
		defaultLogger.file.Close()
	}
}

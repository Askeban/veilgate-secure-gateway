package audit

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAuditRecord_Log(t *testing.T) {
	rec := &AuditRecord{
		Timestamp:    time.Now(),
		EventID:      "test-event-1",
		RequestID:    "req-123",
		UserIdentity: "test-user",
		Action:       "test_action",
		ToolName:     "test_tool",
		InputHash:    "abc123",
		OutputHash:   "def456",
		Status:       "success",
		Latency:      42,
	}

	// Should not panic
	rec.Log()
}

func TestAuditRecord_FileOutput(t *testing.T) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "audit_test_*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	path := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(path)

	// Init audit file
	InitAuditFile(path)
	defer CloseAuditFile()

	// Log a record
	rec := &AuditRecord{
		Timestamp:    time.Now(),
		EventID:      "file-test-1",
		RequestID:    "file-req-1",
		UserIdentity: "file-user",
		Action:       "file_action",
		Status:       "success",
		Latency:      10,
	}
	rec.Log()

	// Log another record
	rec2 := &AuditRecord{
		Timestamp:    time.Now(),
		EventID:      "file-test-2",
		RequestID:    "file-req-2",
		UserIdentity: "file-user",
		Action:       "file_action_2",
		Status:       "error",
		Latency:      5,
	}
	rec2.Log()

	// Read the audit file
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Errorf("Expected 2 audit lines, got %d: %s", len(lines), string(content))
	}

	// Verify first line is valid JSON with expected fields
	var firstRec AuditRecord
	if err := json.Unmarshal([]byte(lines[0]), &firstRec); err != nil {
		t.Errorf("First line is not valid JSON: %s", lines[0])
	}
	if firstRec.EventID != "file-test-1" {
		t.Errorf("Expected event_id 'file-test-1', got '%s'", firstRec.EventID)
	}
	if firstRec.RequestID != "file-req-1" {
		t.Errorf("Expected request_id 'file-req-1', got '%s'", firstRec.RequestID)
	}

	// Verify second line
	var secondRec AuditRecord
	if err := json.Unmarshal([]byte(lines[1]), &secondRec); err != nil {
		t.Errorf("Second line is not valid JSON: %s", lines[1])
	}
	if secondRec.Status != "error" {
		t.Errorf("Expected status 'error', got '%s'", secondRec.Status)
	}
}

func TestComputeHash(t *testing.T) {
	hash := ComputeHash([]byte("hello world"))
	if hash == "" {
		t.Error("Expected non-empty hash")
	}
	if len(hash) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("Expected 64-char hash, got %d chars: %s", len(hash), hash)
	}

	// Same input = same hash
	hash2 := ComputeHash([]byte("hello world"))
	if hash != hash2 {
		t.Error("Same input should produce same hash")
	}

	// Different input = different hash
	hash3 := ComputeHash([]byte("goodbye world"))
	if hash == hash3 {
		t.Error("Different input should produce different hash")
	}
}

func TestInitAuditFile_BadPath(t *testing.T) {
	// Should log error but not crash
	InitAuditFile("/nonexistent/directory/audit.jsonl")
	// If we get here, it didn't crash — that's the test
}

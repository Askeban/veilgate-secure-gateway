package scanner

import (
	"bytes"
	"strings"
	"testing"
)

func TestTokenScanner_ScanStream(t *testing.T) {
	ts := NewTokenScanner()

	tests := []struct {
		name     string
		input    string
		expected string // contains (since redaction might vary slightly by logic) or exact
	}{
		{
			name:     "Simple JSON",
			input:    `{"key": "value"}`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "Multiple Lines",
			input:    "line1\nline2",
			expected: "line1\nline2",
		},
		{
			name:     "Sensitive Data Redaction",
			input:    `{"api_key": "sk-1234567890"}`,
			expected: `{"api_key": "[REDACTED]"}`,
		},
		{
			name:     "Appends Newline",
			input:    "data",
			expected: "data\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := strings.NewReader(tt.input)
			dst := &bytes.Buffer{}

			if err := ts.ScanStream(src, dst); err != nil {
				t.Fatalf("ScanStream failed: %v", err)
			}

			if got := dst.String(); !strings.Contains(got, tt.expected) {
				t.Errorf("ScanStream outcome unexpected.\nGot: %q\nWant: %q", got, tt.expected)
			}

			// Strict check for "Appends Newline" case
			if tt.name == "Appends Newline" {
				if dst.String() != tt.expected {
					t.Errorf("Exact match failed. Got: %q, Want: %q", dst.String(), tt.expected)
				}
			}
		})
	}
}

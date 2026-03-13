package scanner

import (
	"encoding/json"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"secure-mcp-gateway/internal/metrics"
)

// DLPRules defines configurable DLP patterns loaded from JSON
type DLPRules struct {
	InputBlocklist       []string `json:"input_blocklist"`
	OutputRedactPatterns []string `json:"output_redact_patterns"`
	OutputRedactReplace  string   `json:"output_redact_replacement"`
}

// Inspector defines the interface for content inspection
type Inspector interface {
	ScanInput(input string) (bool, string)
	ScanOutput(output string) string
}

type BasicScanner struct {
	rules           DLPRules
	compiledRegexes []*regexp.Regexp
}

func NewBasicScanner() *BasicScanner {
	return NewBasicScannerFromRules("")
}

// NewBasicScannerFromRules loads DLP rules from a JSON file.
// Falls back to sensible defaults if path is empty or file fails to load.
func NewBasicScannerFromRules(rulesPath string) *BasicScanner {
	rules := DLPRules{
		InputBlocklist:       []string{"rm -rf", "wget ", "curl ", ";"},
		OutputRedactPatterns: []string{`sk-[a-zA-Z0-9]{10,}`},
		OutputRedactReplace:  "[REDACTED]",
	}

	if rulesPath != "" {
		b, err := os.ReadFile(rulesPath)
		if err != nil {
			slog.Warn("Failed to load DLP rules, using defaults", "path", rulesPath, "err", err)
		} else {
			if err := json.Unmarshal(b, &rules); err != nil {
				slog.Warn("Failed to parse DLP rules JSON, using defaults", "path", rulesPath, "err", err)
			} else {
				slog.Info("Loaded DLP rules", "path", rulesPath, "input_patterns", len(rules.InputBlocklist), "output_patterns", len(rules.OutputRedactPatterns))
			}
		}
	}

	// Pre-compile output regexes
	var compiled []*regexp.Regexp
	for _, pattern := range rules.OutputRedactPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			slog.Warn("Invalid DLP regex pattern, skipping", "pattern", pattern, "err", err)
			continue
		}
		compiled = append(compiled, re)
	}

	return &BasicScanner{
		rules:           rules,
		compiledRegexes: compiled,
	}
}

func (s *BasicScanner) ScanInput(input string) (bool, string) {
	lower := strings.ToLower(input)
	for _, blocked := range s.rules.InputBlocklist {
		if strings.Contains(lower, strings.ToLower(blocked)) {
			metrics.DLPViolationsTotal.WithLabelValues(blocked).Inc()
			return false, "blocked keyword: " + blocked
		}
	}
	return true, ""
}

func (s *BasicScanner) ScanOutput(output string) string {
	result := output
	metrics.DLPScansTotal.Inc()

	replacement := s.rules.OutputRedactReplace
	if replacement == "" {
		replacement = "[REDACTED]"
	}
	for _, re := range s.compiledRegexes {
		if re.MatchString(result) {
			// Increment the metric specifically for this matched regex pattern
			metrics.DLPRedactionsTotal.WithLabelValues(re.String()).Inc()
			result = re.ReplaceAllString(result, replacement)
		}
	}
	return result
}

package scanner

import (
	"bufio"
	"io"
)

// StreamInspector extends Inspector for streaming data
type StreamInspector interface {
	Inspector
	// ScanStream copies from src to dst while redacting sensitive info
	ScanStream(src io.Reader, dst io.Writer) error
}

type TokenScanner struct {
	*BasicScanner
}

func NewTokenScanner() *TokenScanner {
	return &TokenScanner{
		BasicScanner: NewBasicScanner(),
	}
}

// NewTokenScannerFromRules creates a TokenScanner with DLP rules from a file
func NewTokenScannerFromRules(rulesPath string) *TokenScanner {
	return &TokenScanner{
		BasicScanner: NewBasicScannerFromRules(rulesPath),
	}
}

func (s *TokenScanner) ScanStream(src io.Reader, dst io.Writer) error {
	scanner := bufio.NewScanner(src)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024) // 10MB max token size

	for scanner.Scan() {
		text := scanner.Text()
		redacted := s.ScanOutput(text)

		if _, err := io.WriteString(dst, redacted); err != nil {
			return err
		}
		if _, err := dst.Write([]byte("\n")); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

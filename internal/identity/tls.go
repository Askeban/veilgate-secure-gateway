package identity

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadServerTLSConfig creates a TLS config for the Gateway Server (listening)
func LoadServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load Server Cert/Key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server keypair: %w", err)
	}

	// Load CA for Client Auth (mTLS)
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ca file: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append ca certs")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// LoadClientTLSConfig creates a TLS config for the Proxy Client (calling Upstream)
func LoadClientTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load Client Cert/Key (if presented to upstream)
	var certs []tls.Certificate
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client keypair: %w", err)
		}
		certs = append(certs, cert)
	}

	// Load Upstream CA (to verify upstream)
	var caPool *x509.CertPool
	if caFile != "" {
		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read upstream ca file: %w", err)
		}
		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to append upstream ca certs")
		}
	}

	return &tls.Config{
		Certificates: certs,
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

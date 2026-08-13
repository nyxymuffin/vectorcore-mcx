// Package tlsutil builds the tls.Config shared by the HTTP listeners.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
)

// ServerConfig materialises the tls section into a server-side tls.Config.
// It returns (nil, nil) when TLS is disabled, so callers can branch on the
// result alone.
func ServerConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}

	out := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion(cfg.MinVersion),
	}

	if strings.TrimSpace(cfg.ClientCAFile) != "" {
		pool := x509.NewCertPool()
		pem, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA bundle: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client CA bundle %s contains no usable certificates", cfg.ClientCAFile)
		}
		out.ClientCAs = pool
		out.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return out, nil
}

// minVersion maps the validated config string. Validate has already rejected
// anything else, so the default arm is unreachable in a loaded config and
// exists only to make direct construction safe.
func minVersion(v string) uint16 {
	if v == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

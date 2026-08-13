package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
)

// writeTestCert writes a self-signed server certificate for 127.0.0.1 and
// returns the cert path, key path, and the certificate itself for pinning.
func writeTestCert(t *testing.T, dir string) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mcxas test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, cert
}

func TestServerConfigDisabledReturnsNil(t *testing.T) {
	conf, err := ServerConfig(config.TLSConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if conf != nil {
		t.Fatal("disabled TLS must produce a nil config so callers can branch on it")
	}
}

func TestServerConfigRejectsMissingKeypair(t *testing.T) {
	_, err := ServerConfig(config.TLSConfig{
		Enabled:  true,
		CertFile: filepath.Join(t.TempDir(), "absent.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "absent-key.pem"),
	})
	if err == nil {
		t.Fatal("a missing keypair must fail at construction, not at first handshake")
	}
}

// End to end: a client that trusts the certificate can complete a handshake
// and a request against a listener built from this config.
func TestServerConfigServesHTTPS(t *testing.T) {
	certFile, keyFile, cert := writeTestCert(t, t.TempDir())

	conf, err := ServerConfig(config.TLSConfig{
		Enabled: true, CertFile: certFile, KeyFile: keyFile, MinVersion: "1.2",
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = conf
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatal("connection was not TLS")
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated TLS version %x is below the configured minimum", resp.TLS.Version)
	}
}

// With a client CA configured, a client without a certificate must be refused.
// Half-configured mutual TLS that silently admits everyone would be worse
// than no option at all.
func TestServerConfigEnforcesClientCertificates(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, cert := writeTestCert(t, dir)

	conf, err := ServerConfig(config.TLSConfig{
		Enabled:      true,
		CertFile:     certFile,
		KeyFile:      keyFile,
		ClientCAFile: certFile, // the self-signed cert doubles as the client CA
		MinVersion:   "1.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if conf.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", conf.ClientAuth)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = conf
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	// No client certificate: the handshake must fail.
	bare := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	if resp, err := bare.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("request without a client certificate succeeded against mutual TLS")
	}

	// With the server's own keypair presented as the client certificate
	// (issued by the same CA), the request must succeed.
	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	mutual := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
	}}}
	resp, err := mutual.Get(srv.URL)
	if err != nil {
		t.Fatalf("mutual TLS request failed: %v", err)
	}
	resp.Body.Close()
}

func TestServerConfigRejectsUselessClientCABundle(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeTestCert(t, dir)

	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ServerConfig(config.TLSConfig{
		Enabled: true, CertFile: certFile, KeyFile: keyFile, ClientCAFile: junk,
	})
	if err == nil {
		t.Fatal("a client CA bundle with no usable certificates must be rejected")
	}
}

func TestMinVersionMapping(t *testing.T) {
	if got := minVersion("1.3"); got != tls.VersionTLS13 {
		t.Fatalf("1.3 mapped to %x", got)
	}
	if got := minVersion("1.2"); got != tls.VersionTLS12 {
		t.Fatalf("1.2 mapped to %x", got)
	}
}

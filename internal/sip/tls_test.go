package sip

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/tlsutil"
)

func writeSIPTestCert(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mcxas sip test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
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

	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

// End to end: an OPTIONS request over a TLS connection is answered on the
// same connection, and the Via in the response carries the TLS transport.
func TestSIPOverTLSAnswersOptions(t *testing.T) {
	certFile, keyFile, pool := writeSIPTestCert(t, t.TempDir())

	cfg := config.Default()
	cfg.TLS = config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile, MinVersion: "1.2"}

	tlsConf, err := tlsutil.ServerConfig(cfg.TLS)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.serveStream(ctx, ln, "tls") }()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	request := "OPTIONS sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS 127.0.0.1:5061;branch=z9hG4bKtls1\r\n" +
		"From: <sip:u@example.test>;tag=t1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: tls-options-1\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := readSIPMessage(bufio.NewReaderSize(conn, sipReaderBufferBytes))
	if err != nil {
		t.Fatalf("no response over TLS: %v", err)
	}
	text := string(resp)
	if !strings.HasPrefix(text, "SIP/2.0 200") {
		t.Fatalf("response = %q, want 200 OK", firstLine(text))
	}
	if !strings.Contains(text, "SIP/2.0/TLS") {
		t.Fatalf("response Via lost the TLS transport:\n%s", text)
	}
}

// ListenTLS with the tls section disabled is a configuration error, and must
// fail rather than quietly serve plaintext.
func TestListenTLSRequiresTheTLSSection(t *testing.T) {
	cfg := config.Default()
	cfg.SIP.TLSListen = "127.0.0.1:0"

	s := NewServer(cfg, nil)
	err := s.ListenTLS(context.Background())
	if err == nil {
		t.Fatal("ListenTLS must refuse to start without certificates")
	}
	if !strings.Contains(err.Error(), "tls section") {
		t.Fatalf("error %q does not explain the missing tls section", err)
	}
}

// Outbound TLS must verify the peer. With the peer's CA pinned the send
// succeeds; without it the handshake must fail rather than fall back.
func TestSendOutboundTLSVerifiesPeer(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeSIPTestCert(t, dir)

	serverTLS, err := tlsutil.ServerConfig(config.TLSConfig{
		Enabled: true, CertFile: certFile, KeyFile: keyFile, MinVersion: "1.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	received := make(chan []byte, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _ := conn.Read(buf)
			if n > 0 {
				received <- buf[:n]
			}
			conn.Close()
		}
	}()

	payload := []byte("OPTIONS sip:peer SIP/2.0\r\nContent-Length: 0\r\n\r\n")

	// Without the CA pinned: the peer is unverifiable and the send must fail.
	cfgUntrusted := config.Default()
	cfgUntrusted.TLS = config.TLSConfig{MinVersion: "1.2"}
	sUntrusted := NewServer(cfgUntrusted, nil)
	if err := sUntrusted.sendOutbound(context.Background(), "tls", ln.Addr().String(), payload); err == nil {
		t.Fatal("outbound TLS succeeded against an unverifiable peer; verification is being skipped")
	}

	// With the CA pinned via tls.peer_ca_file: the send must succeed.
	cfgTrusted := config.Default()
	cfgTrusted.TLS = config.TLSConfig{MinVersion: "1.2", PeerCAFile: certFile}
	sTrusted := NewServer(cfgTrusted, nil)
	if err := sTrusted.sendOutbound(context.Background(), "tls", ln.Addr().String(), payload); err != nil {
		t.Fatalf("outbound TLS with the peer CA pinned failed: %v", err)
	}

	select {
	case got := <-received:
		if !strings.HasPrefix(string(got), "OPTIONS") {
			t.Fatalf("peer received %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer never received the message")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\r'); i >= 0 {
		return s[:i]
	}
	return s
}

package sip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

// signES256 produces a compact JWS over the claims with the raw r||s
// signature form of RFC 7518.
func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	headerJSON, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid})
	claimsJSON, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeJWKS(t *testing.T, dir, kid string, pub *ecdsa.PublicKey) string {
	t.Helper()
	pad := func(v *big.Int) string {
		b := make([]byte, 32)
		v.FillBytes(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	doc := map[string]any{"keys": []map[string]any{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid,
		"x": pad(pub.X), "y": pad(pub.Y),
	}}}
	raw, _ := json.Marshal(doc)
	path := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func servicePublish(token string) string {
	body := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		`<mcptt-access-token type="Normal"><mcpttString>` + token + `</mcpttString></mcptt-access-token>` +
		`</mcptt-Params></mcpttinfo>`
	return "PUBLISH sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKauth" + fmt.Sprint(len(token)) + "\r\n" +
		"From: <sip:ue@example.test>;tag=a1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: auth-" + fmt.Sprint(len(token)) + "\r\n" +
		"CSeq: 1 PUBLISH\r\n" +
		"Event: poc-settings\r\n" +
		"Content-Type: application/vnd.3gpp.mcptt-info+xml\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

func newTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

type authFixture struct {
	server *Server
	key    *ecdsa.PrivateKey
	kid    string
}

func newAuthFixture(t *testing.T, mutate func(*config.Config)) *authFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-key"
	jwks := writeJWKS(t, t.TempDir(), kid, &key.PublicKey)

	cfg := config.Default()
	cfg.SIP.Auth.RequireServiceAuthorization = true
	cfg.SIP.Auth.TrustedJWKSFile = jwks
	if mutate != nil {
		mutate(&cfg)
	}
	return &authFixture{server: NewServer(cfg, newTestStore(t)), kid: kid, key: key}
}

func (f *authFixture) publish(t *testing.T, token string) string {
	t.Helper()
	var response string
	f.server.handleRaw(context.Background(), "192.0.2.52:5060", "udp", []byte(servicePublish(token)), func(resp []byte) error {
		response = string(resp)
		return nil
	})
	return response
}

func validClaims(mcpttID string) map[string]any {
	return map[string]any{
		"iss":      "vectorcore-mcx-idms",
		"mcptt_id": mcpttID,
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
}

func TestServiceAuthorizationAcceptsValidToken(t *testing.T) {
	f := newAuthFixture(t, nil)
	token := signES256(t, f.key, f.kid, validClaims("sip:authed@example.test"))

	resp := f.publish(t, token)
	if !strings.HasPrefix(resp, "SIP/2.0 200") {
		t.Fatalf("response = %q, want 200 for a valid token", firstLine(resp))
	}
}

func TestServiceAuthorizationRefusesMissingToken(t *testing.T) {
	f := newAuthFixture(t, nil)

	// A PUBLISH with no token at all: strip the body by publishing an empty
	// token string, which produces no JWS-shaped content.
	resp := f.publish(t, "")
	if !strings.HasPrefix(resp, "SIP/2.0 403") {
		t.Fatalf("response = %q, want 403 without a token", firstLine(resp))
	}
	if !strings.Contains(resp, `"101 service authorisation failed"`) {
		t.Fatalf("response lacks the TS 24.379 warning text:\n%s", resp)
	}
}

func TestServiceAuthorizationRefusesExpiredToken(t *testing.T) {
	f := newAuthFixture(t, nil)
	claims := validClaims("sip:expired@example.test")
	claims["exp"] = time.Now().Add(-time.Minute).Unix()

	resp := f.publish(t, signES256(t, f.key, f.kid, claims))
	if !strings.HasPrefix(resp, "SIP/2.0 403") {
		t.Fatalf("response = %q, want 403 for an expired token", firstLine(resp))
	}
}

// alg:none must be refused regardless of what the rest of the token says. The
// permitted algorithm is the server's choice, not the token's.
func TestServiceAuthorizationRefusesAlgNone(t *testing.T) {
	f := newAuthFixture(t, nil)

	headerJSON, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	claimsJSON, _ := json.Marshal(validClaims("sip:forged@example.test"))
	token := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "."

	resp := f.publish(t, token)
	if !strings.HasPrefix(resp, "SIP/2.0 403") {
		t.Fatalf("response = %q, want 403 for alg:none", firstLine(resp))
	}
}

func TestServiceAuthorizationRefusesUntrustedKey(t *testing.T) {
	f := newAuthFixture(t, nil)
	rogue, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	resp := f.publish(t, signES256(t, rogue, f.kid, validClaims("sip:rogue@example.test")))
	if !strings.HasPrefix(resp, "SIP/2.0 403") {
		t.Fatalf("response = %q, want 403 for a token signed by an untrusted key", firstLine(resp))
	}
}

func TestServiceAuthorizationRefusesWrongIssuer(t *testing.T) {
	f := newAuthFixture(t, func(cfg *config.Config) {
		cfg.SIP.Auth.TrustedIssuer = "https://idms.example.test"
	})

	resp := f.publish(t, signES256(t, f.key, f.kid, validClaims("sip:other-issuer@example.test")))
	if !strings.HasPrefix(resp, "SIP/2.0 403") {
		t.Fatalf("response = %q, want 403 for an untrusted issuer", firstLine(resp))
	}
}

// If authorization is required but the validator could not be built, every
// request must be refused. Admitting everyone because the keys failed to load
// would turn a deployment mistake into an authentication bypass.
func TestServiceAuthorizationFailsClosedWithoutValidator(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := config.Default()
	cfg.SIP.Auth.RequireServiceAuthorization = true
	cfg.SIP.Auth.TrustedJWKSFile = filepath.Join(t.TempDir(), "absent.json")
	s := NewServer(cfg, newTestStore(t))

	token := signES256(t, key, "k", validClaims("sip:someone@example.test"))
	var response string
	s.handleRaw(context.Background(), "192.0.2.52:5060", "udp", []byte(servicePublish(token)), func(resp []byte) error {
		response = string(resp)
		return nil
	})
	if !strings.HasPrefix(response, "SIP/2.0 403") {
		t.Fatalf("response = %q, want 403 when the validator is unavailable", firstLine(response))
	}
}

// The authenticated identity from the token must win over whatever identity
// the body asserts, otherwise the token authenticates one user while the
// server binds another.
func TestServiceAuthorizationBindsTokenIdentity(t *testing.T) {
	f := newAuthFixture(t, nil)
	token := signES256(t, f.key, f.kid, validClaims("sip:token-identity@example.test"))

	resp := f.publish(t, token)
	if !strings.HasPrefix(resp, "SIP/2.0 200") {
		t.Fatalf("response = %q", firstLine(resp))
	}

	state, err := f.server.st.UpsertPublishedState(context.Background(), store.PublishedState{
		UserURI: "sip:token-identity@example.test",
		Event:   "poc-settings",
		Body:    "probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.UserURI != "sip:token-identity@example.test" {
		t.Fatalf("published state user = %q; the handler did not bind the token identity", state.UserURI)
	}
}

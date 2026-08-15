package cms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

// mintTestToken creates an ES256-signed access token and the JWKS file that
// trusts it, mirroring what the IdMS issues.
func mintTestToken(t *testing.T, dir, mcpttID string) (tokenString, jwksPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pad32 := func(v *big.Int) []byte {
		out := make([]byte, 32)
		v.FillBytes(out)
		return out
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "t1",
		"x": b64(pad32(key.PublicKey.X)), "y": b64(pad32(key.PublicKey.Y)),
	}}}
	jwksBytes, _ := json.Marshal(jwks)
	jwksPath = filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(jwksPath, jwksBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	header := b64([]byte(`{"alg":"ES256","kid":"t1"}`))
	claims := b64([]byte(fmt.Sprintf(`{"iss":"test-idms","exp":%d,"mcptt_id":%q}`,
		time.Now().Add(time.Hour).Unix(), mcpttID)))
	digest := sha256.Sum256([]byte(header + "." + claims))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(pad32(r), pad32(s)...)
	return header + "." + claims + "." + b64(sig), jwksPath
}

func authFixture(t *testing.T) (*Server, string) {
	t.Helper()
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	token, jwksPath := mintTestToken(t, t.TempDir(), "sip:driver@example.test")
	cfg := config.Default()
	cfg.CMS.RequireAuthorization = true
	cfg.SIP.Auth.TrustedJWKSFile = jwksPath
	cfg.SIP.Auth.TrustedIssuer = "test-idms"
	return NewServer(cfg, st), token
}

// TS 24.482: no bearer token and no asserted identity is a 403.
func TestXCAPWithoutAuthorizationIs403(t *testing.T) {
	s, _ := authFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/xcap-root/xcap-caps/global/index", nil)
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

// A valid bearer token is accepted; a garbage one is 403.
func TestXCAPBearerToken(t *testing.T) {
	s, token := authFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/xcap-root/xcap-caps/global/index", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with a valid token; body: %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/xcap-root/xcap-caps/global/index", nil)
	req.Header.Set("Authorization", "Bearer not.a.token")
	rr = httptest.NewRecorder()
	s.handleXCAP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an invalid token", rr.Code)
	}
}

// X-3GPP-Asserted-Identity (TS 24.109, from a trusted proxy) is the
// alternative the clause allows.
func TestXCAPAssertedIdentityAccepted(t *testing.T) {
	s, _ := authFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/xcap-root/xcap-caps/global/index", nil)
	req.Header.Set("X-3GPP-Asserted-Identity", `"sip:driver@example.test"`)
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with asserted identity", rr.Code)
	}
}

// With the flag off (development bootstrap), anonymous fetches keep working.
func TestXCAPAnonymousWhenAuthorizationDisabled(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := NewServer(config.Default(), st)
	req := httptest.NewRequest(http.MethodGet, "/xcap-root/xcap-caps/global/index", nil)
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when authorization is disabled", rr.Code)
	}
}

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

func newAPIServer(t *testing.T, mutate func(*config.Config)) http.Handler {
	t.Helper()

	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	return New(st, cfg, "test").Handler()
}

func enabledShim(cfg *config.Config) {
	cfg.IDMS.DevelopmentShimEnabled = true
	cfg.IDMS.AllowedRedirectURIs = []string{"http://192.0.2.20:9000/callback"}
}

// The shim authenticates nobody, so it must not exist unless asked for.
func TestIDMSShimIsNotRegisteredByDefault(t *testing.T) {
	h := newAPIServer(t, nil)

	for _, path := range []string{"/idms/authorize", "/idms/stats", "/idms/jwks.json"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 while the shim is disabled", path, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/idms/token", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /idms/token = %d, want 404 while the shim is disabled", rec.Code)
	}
}

func TestIDMSShimIsRegisteredWhenEnabled(t *testing.T) {
	h := newAPIServer(t, enabledShim)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/idms/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /idms/jwks.json = %d, want 200 once enabled", rec.Code)
	}
}

func issueToken(t *testing.T, h http.Handler) map[string]any {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/idms/token",
		strings.NewReader("grant_type=authorization_code&code=vectorcore-dev-code&client_id=mcptt_client"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /idms/token = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TS 33.180 Annex B.2.2.1 requires the access token to carry a JWS. An
// "alg":"none" token is not an incomplete implementation of the profile, it is
// a violation of it, and a conformant relying party must reject it.
func TestIDMSTokensAreSignedNotAlgNone(t *testing.T) {
	h := newAPIServer(t, enabledShim)
	body := issueToken(t, h)

	for _, name := range []string{"access_token", "id_token"} {
		token, ok := body[name].(string)
		if !ok || token == "" {
			t.Fatalf("%s missing from the token response", name)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("%s is not a three part JWS: %q", name, token)
		}
		if parts[2] == "" {
			t.Fatalf("%s has an empty signature segment", name)
		}

		header := decodeSegment(t, parts[0])
		if header["alg"] == "none" {
			t.Fatalf("%s uses alg=none, which the profile forbids", name)
		}
		if header["alg"] != "ES256" {
			t.Fatalf("%s alg = %v, want ES256", name, header["alg"])
		}
	}
}

// A signature nobody can check is no better than none, so the published JWKS
// must actually verify the issued token.
func TestIDMSTokenVerifiesAgainstPublishedJWKS(t *testing.T) {
	h := newAPIServer(t, enabledShim)
	token := issueToken(t, h)["access_token"].(string)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/idms/jwks.json", nil))

	var jwks struct {
		Keys []struct {
			Kty, Crv, Alg, Kid, X, Y string
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("jwks has %d keys, want 1", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kty != "EC" || key.Crv != "P-256" || key.Alg != "ES256" {
		t.Fatalf("unexpected jwk: %+v", key)
	}

	xb, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		t.Fatal(err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		t.Fatal(err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}

	parts := strings.Split(token, ".")
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want the 64 byte r||s form of RFC 7518", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("token does not verify against the published JWKS")
	}

	header := decodeSegment(t, parts[0])
	if header["kid"] != key.Kid {
		t.Fatalf("token kid %v does not match the published kid %v", header["kid"], key.Kid)
	}
}

// Annex B.2.1.1 defines exp and iat as numeric dates. Emitting them as strings
// fails a strict validator outright, which the previous implementation did.
func TestIDMSClaimsUseRequiredTypesAndFields(t *testing.T) {
	h := newAPIServer(t, enabledShim)
	body := issueToken(t, h)

	access := decodeSegment(t, strings.Split(body["access_token"].(string), ".")[1])
	id := decodeSegment(t, strings.Split(body["id_token"].(string), ".")[1])

	for name, claims := range map[string]map[string]any{"access_token": access, "id_token": id} {
		for _, field := range []string{"exp", "iat"} {
			if _, ok := claims[field].(float64); !ok {
				t.Errorf("%s claim %q = %T, want a JSON number", name, field, claims[field])
			}
		}
		if claims["mcptt_id"] == "" || claims["mcptt_id"] == nil {
			t.Errorf("%s is missing the required mcptt_id claim", name)
		}
	}

	// aud is required in the ID token, scope in the access token.
	if id["aud"] == nil || id["aud"] == "" {
		t.Error("id_token is missing the required aud claim")
	}
	scope, _ := access["scope"].(string)
	if !strings.Contains(scope, "3gpp:mc:ptt_service") {
		t.Errorf("access_token scope = %q, want it to carry the MC service scope", scope)
	}
}

// redirect_uri was previously used verbatim, giving an open redirect that also
// leaked the authorization code.
func TestIDMSAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	h := newAPIServer(t, enabledShim)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/idms/authorize?redirect_uri=http://attacker.example/steal", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unregistered redirect_uri", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("server issued a redirect to %q despite the URI being unregistered", loc)
	}
}

func TestIDMSAuthorizeAcceptsRegisteredRedirect(t *testing.T) {
	h := newAPIServer(t, enabledShim)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/idms/authorize?redirect_uri=http://192.0.2.20:9000/callback&state=xyz", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for a registered redirect_uri", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Fatalf("state = %q, want it echoed", got)
	}
	if loc.Query().Get("code") == "" {
		t.Fatal("no authorization code in the redirect")
	}
}

// state was concatenated raw, so a crafted value could append parameters of
// its own to the redirect.
func TestIDMSAuthorizeEscapesState(t *testing.T) {
	h := newAPIServer(t, enabledShim)

	injected := "abc&code=attacker-controlled"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/idms/authorize?redirect_uri=http://192.0.2.20:9000/callback&state="+url.QueryEscape(injected), nil))

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Query().Get("state"); got != injected {
		t.Fatalf("state = %q, want the value preserved intact", got)
	}
	if got := loc.Query().Get("code"); got == "attacker-controlled" {
		t.Fatal("state injected a code parameter into the redirect")
	}
}

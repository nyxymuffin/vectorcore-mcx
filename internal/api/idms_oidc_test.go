package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

func oidcFixture(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.CreateUser(context.Background(), store.User{
		IMPU: "sip:driver@example.test", MCPTTID: "sip:driver@example.test",
		MCID: "driver", Password: "correct horse battery staple", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.IDMS.Enabled = true
	cfg.IDMS.Issuer = "test-idms"
	cfg.IDMS.AllowedClientIDs = []string{"mcptt_client"}
	cfg.IDMS.AllowedRedirectURIs = []string{"http://3gpp.mcptt/cb"}
	s := New(st, cfg, "test")
	return s, s.Handler()
}

// pkce returns a verifier and its S256 challenge.
func pkce() (verifier, challenge string) {
	verifier = "0123456789abcdef0123456789abcdef0123456789abcdef"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeParams(challenge string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"mcptt_client"},
		"redirect_uri":          {"http://3gpp.mcptt/cb"},
		"scope":                 {"openid 3gpp:mc:ptt_service 3gpp:mc:video_service"},
		"state":                 {"abc123"},
		"acr_values":            {"3gpp:acr:password"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

// The full Annex B code flow: login form, password auth, code redirect with
// state, PKCE-verified token exchange, scoped tokens, working refresh.
func TestOIDCCodeFlowWithPKCE(t *testing.T) {
	_, h := oidcFixture(t)
	verifier, challenge := pkce()

	// GET renders the login form.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/idms/authorize?"+authorizeParams(challenge).Encode(), nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "MCX Sign In") {
		t.Fatalf("authorize form: status=%d body:\n%s", rr.Code, rr.Body.String())
	}

	// POST with credentials redirects with code + state.
	form := authorizeParams(challenge)
	form.Set("username", "driver")
	form.Set("password", "correct horse battery staple")
	req := httptest.NewRequest(http.MethodPost, "/idms/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize submit: status=%d body:\n%s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != "abc123" {
		t.Fatalf("state not echoed: %s", loc)
	}
	code := loc.Query().Get("code")
	if code == "" || code == "vectorcore-dev-code" {
		t.Fatalf("code missing or the shim's fixed value: %q", code)
	}

	// Token exchange with the PKCE verifier.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"mcptt_client"},
		"redirect_uri":  {"http://3gpp.mcptt/cb"},
		"code_verifier": {verifier},
	}
	req = httptest.NewRequest(http.MethodPost, "/idms/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("token: status=%d body:\n%s", rr.Code, rr.Body.String())
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" || tok.IDToken == "" || tok.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", tok)
	}
	// Scope intersected with what this deployment serves: the MCVideo scope
	// requested above must not survive (out of scope by decision).
	if !strings.Contains(tok.Scope, "3gpp:mc:ptt_service") || strings.Contains(tok.Scope, "video") {
		t.Fatalf("scope = %q", tok.Scope)
	}
	// The access token carries mcptt_id, scope and client_id (Annex B.2.2.2).
	claims := decodeClaims(t, tok.AccessToken)
	if claims["mcptt_id"] != "sip:driver@example.test" || claims["client_id"] != "mcptt_client" {
		t.Fatalf("access claims: %v", claims)
	}
	// The ID token carries aud (Annex B.2.1.2).
	if decodeClaims(t, tok.IDToken)["aud"] != "mcptt_client" {
		t.Fatalf("id token aud missing")
	}

	// The code is single use: replaying it fails.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/idms/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("replayed code: status=%d, want 400", rr.Code)
	}

	// Refresh rotates and returns a new access token (Annex B.5).
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {"mcptt_client"},
	}
	req = httptest.NewRequest(http.MethodPost, "/idms/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh: status=%d body:\n%s", rr.Code, rr.Body.String())
	}
	// The used refresh token no longer works (rotation).
	req = httptest.NewRequest(http.MethodPost, "/idms/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("rotated refresh token still worked: %d", rr.Code)
	}
}

// A wrong password is refused; a wrong PKCE verifier kills the exchange.
func TestOIDCRejectsBadCredentialsAndBadVerifier(t *testing.T) {
	_, h := oidcFixture(t)
	_, challenge := pkce()

	form := authorizeParams(challenge)
	form.Set("username", "driver")
	form.Set("password", "wrong")
	req := httptest.NewRequest(http.MethodPost, "/idms/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: status=%d, want 401", rr.Code)
	}

	// Right password, wrong verifier at the token endpoint.
	form.Set("password", "correct horse battery staple")
	req = httptest.NewRequest(http.MethodPost, "/idms/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"mcptt_client"},
		"redirect_uri":  {"http://3gpp.mcptt/cb"},
		"code_verifier": {"not-the-right-verifier-at-all-not-the-right"},
	}
	req = httptest.NewRequest(http.MethodPost, "/idms/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad verifier: status=%d, want 400", rr.Code)
	}
}

// The Annex B.4.2.2 required parameters are enforced.
func TestOIDCAuthorizeParameterValidation(t *testing.T) {
	_, h := oidcFixture(t)
	_, challenge := pkce()
	for name, mutate := range map[string]func(url.Values){
		"missing pkce":        func(q url.Values) { q.Del("code_challenge") },
		"plain pkce":          func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"unregistered client": func(q url.Values) { q.Set("client_id", "evil") },
		"foreign redirect":    func(q url.Values) { q.Set("redirect_uri", "http://evil.example/cb") },
		"no openid scope":     func(q url.Values) { q.Set("scope", "3gpp:mc:ptt_service") },
		"no state":            func(q url.Values) { q.Del("state") },
	} {
		q := authorizeParams(challenge)
		mutate(q)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/idms/authorize?"+q.Encode(), nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d, want 400", name, rr.Code)
		}
	}
}

func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

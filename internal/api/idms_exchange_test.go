package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/mctoken"
)

func postToken(t *testing.T, h http.Handler, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/idms/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	body := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr, body
}

// accessToken drives the full code flow and returns a locally issued
// access token, which is the subject_token of clause B.7.2.
func accessToken(t *testing.T, s *Server) string {
	t.Helper()
	token, err := s.idmsSigner.sign(map[string]any{
		"iss":       s.idmsIssuer(),
		"sub":       "sip:driver@example.test",
		"mcptt_id":  "sip:driver@example.test",
		"client_id": "mcptt_client",
		"scope":     "3gpp:mc:ptt_service",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Clauses B.7.2 and B.7.3: the primary IdMS exchanges a user's access
// token for a security token addressed to the named partner.
func TestTokenExchangeIssuesSecurityToken(t *testing.T) {
	s, h := oidcFixture(t)

	rr, body := postToken(t, h, url.Values{
		"grant_type":         {grantTokenExchange},
		"resource":           {"https://idm.partner.test/token"},
		"subject_token":      {accessToken(t, s)},
		"subject_token_type": {tokenTypeJWT},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rr.Code, rr.Body.String())
	}
	if body["issued_token_type"] != tokenTypeJWT {
		t.Fatalf("issued_token_type = %v", body["issued_token_type"])
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v", body["token_type"])
	}
	if body["expires_in"] == nil {
		t.Fatal("no expires_in in the token exchange response")
	}

	security, _ := body["access_token"].(string)
	claims, err := s.idmsSigner.verify(security, s.idmsIssuer(), time.Now())
	if err != nil {
		t.Fatalf("the security token does not verify: %v", err)
	}
	// Table B.8-1: the audience carries the client ID and the address of
	// the target IdMS.
	if !audienceAccepts(claims["aud"], "https://idm.partner.test/token") {
		t.Fatalf("aud = %v, want the resource", claims["aud"])
	}
	if !audienceAccepts(claims["aud"], "mcptt_client") {
		t.Fatalf("aud = %v, want the client id", claims["aud"])
	}
	if claims["sub"] != "sip:driver@example.test" {
		t.Fatalf("sub = %v", claims["sub"])
	}
}

// Table B.7.2-1 fixes the subject token type, and a subject token this
// server did not issue is not exchanged.
func TestTokenExchangeChecksItsInput(t *testing.T) {
	s, h := oidcFixture(t)
	valid := accessToken(t, s)

	for name, form := range map[string]url.Values{
		"wrong token type": {
			"grant_type": {grantTokenExchange}, "resource": {"https://idm.partner.test/token"},
			"subject_token": {valid}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		},
		"no resource": {
			"grant_type": {grantTokenExchange}, "subject_token": {valid},
			"subject_token_type": {tokenTypeJWT},
		},
		"foreign subject token": {
			"grant_type": {grantTokenExchange}, "resource": {"https://idm.partner.test/token"},
			"subject_token":      {"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhIn0.AAAA"},
			"subject_token_type": {tokenTypeJWT},
		},
	} {
		if rr, _ := postToken(t, h, form); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", name, rr.Code)
		}
	}
}

// partnerFixture points a server at a second server as its trusted
// primary IdMS, which is the deployment of clause B.7.4.
func partnerFixture(t *testing.T, primary *Server) (*Server, http.Handler) {
	t.Helper()
	jwksPath := filepath.Join(t.TempDir(), "primary-jwks.json")
	raw, err := json.Marshal(primary.idmsSigner.jwks())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jwksPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	s, h := oidcFixture(t)
	s.cfg.IDMS.Issuer = "partner-idms"
	s.partnerIdMS = map[string]*mctoken.Validator{}
	validator, err := mctoken.New(jwksPath, primary.idmsIssuer())
	if err != nil {
		t.Fatal(err)
	}
	s.partnerIdMS[primary.idmsIssuer()] = validator
	return s, h
}

// Clauses B.7.4 and B.7.5: the partner IdMS accepts the security token as
// a JWT bearer assertion and returns its own access token.
func TestJWTBearerAssertionIssuesPartnerAccessToken(t *testing.T) {
	primary, primaryHandler := oidcFixture(t)
	partner, partnerHandler := partnerFixture(t, primary)

	_, exchanged := postToken(t, primaryHandler, url.Values{
		"grant_type":         {grantTokenExchange},
		"resource":           {partner.idmsIssuer()},
		"subject_token":      {accessToken(t, primary)},
		"subject_token_type": {tokenTypeJWT},
	})
	security, _ := exchanged["access_token"].(string)
	if security == "" {
		t.Fatal("the primary issued no security token")
	}

	rr, body := postToken(t, partnerHandler, url.Values{
		"grant_type": {grantJWTBearer},
		"assertion":  {security},
		"client_id":  {"mcptt_client"},
		"scope":      {"openid 3gpp:mc:ptt_service 3gpp:mc:ptt_group_management_service"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rr.Code, rr.Body.String())
	}
	if body["token_type"] != "Bearer" || body["expires_in"] == nil {
		t.Fatalf("malformed token response: %v", body)
	}

	// Clause B.9: the partner's access token is an ordinary access token,
	// carrying the user and the scopes granted in the partner domain.
	issued, _ := body["access_token"].(string)
	claims, err := partner.idmsSigner.verify(issued, partner.idmsIssuer(), time.Now())
	if err != nil {
		t.Fatalf("the partner access token does not verify: %v", err)
	}
	if claims["sub"] != "sip:driver@example.test" {
		t.Fatalf("sub = %v", claims["sub"])
	}
	scope, _ := claims["scope"].(string)
	if !strings.Contains(scope, "3gpp:mc:ptt_group_management_service") {
		t.Fatalf("scope = %q, want the requested group management service", scope)
	}
}

// An assertion signed by nobody the partner trusts, or addressed to a
// different domain, is refused: clause B.7.4 requires the partner to
// authenticate the security token before exchanging it.
func TestJWTBearerAssertionChecks(t *testing.T) {
	primary, primaryHandler := oidcFixture(t)
	partner, partnerHandler := partnerFixture(t, primary)

	// Addressed to somebody else.
	_, elsewhere := postToken(t, primaryHandler, url.Values{
		"grant_type":         {grantTokenExchange},
		"resource":           {"https://idm.third-party.test/token"},
		"subject_token":      {accessToken(t, primary)},
		"subject_token_type": {tokenTypeJWT},
	})
	misaddressed, _ := elsewhere["access_token"].(string)
	if rr, _ := postToken(t, partnerHandler, url.Values{
		"grant_type": {grantJWTBearer}, "assertion": {misaddressed},
		"client_id": {"mcptt_client"}, "scope": {"3gpp:mc:ptt_service"},
	}); rr.Code != http.StatusBadRequest {
		t.Fatalf("a misaddressed assertion was accepted: %d", rr.Code)
	}

	// Signed by an untrusted issuer: the partner's own token is not a
	// security token from its primary.
	local := accessToken(t, partner)
	if rr, _ := postToken(t, partnerHandler, url.Values{
		"grant_type": {grantJWTBearer}, "assertion": {local},
		"client_id": {"mcptt_client"}, "scope": {"3gpp:mc:ptt_service"},
	}); rr.Code != http.StatusBadRequest {
		t.Fatalf("an untrusted assertion was accepted: %d", rr.Code)
	}

	// An unregistered client cannot exchange even a valid assertion
	// (clause B.3 client registration).
	_, valid := postToken(t, primaryHandler, url.Values{
		"grant_type":         {grantTokenExchange},
		"resource":           {partner.idmsIssuer()},
		"subject_token":      {accessToken(t, primary)},
		"subject_token_type": {tokenTypeJWT},
	})
	security, _ := valid["access_token"].(string)
	if rr, _ := postToken(t, partnerHandler, url.Values{
		"grant_type": {grantJWTBearer}, "assertion": {security},
		"client_id": {"unknown_client"}, "scope": {"3gpp:mc:ptt_service"},
	}); rr.Code != http.StatusBadRequest {
		t.Fatalf("an unregistered client was served: %d", rr.Code)
	}
}

// A domain with no configured partners refuses every assertion rather
// than falling back to accepting unverified ones.
func TestNoPartnersConfiguredRefusesAssertions(t *testing.T) {
	primary, primaryHandler := oidcFixture(t)
	_, bare := oidcFixture(t)

	_, exchanged := postToken(t, primaryHandler, url.Values{
		"grant_type":         {grantTokenExchange},
		"resource":           {"test-idms"},
		"subject_token":      {accessToken(t, primary)},
		"subject_token_type": {tokenTypeJWT},
	})
	security, _ := exchanged["access_token"].(string)

	if rr, _ := postToken(t, bare, url.Values{
		"grant_type": {grantJWTBearer}, "assertion": {security},
		"client_id": {"mcptt_client"}, "scope": {"3gpp:mc:ptt_service"},
	}); rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

// Table B.7.4-1 makes the scope required, and it must name at least one
// MC resource server this domain recognises.
func TestJWTBearerAssertionRequiresAScope(t *testing.T) {
	primary, primaryHandler := oidcFixture(t)
	partner, partnerHandler := partnerFixture(t, primary)

	_, exchanged := postToken(t, primaryHandler, url.Values{
		"grant_type":         {grantTokenExchange},
		"resource":           {partner.idmsIssuer()},
		"subject_token":      {accessToken(t, primary)},
		"subject_token_type": {tokenTypeJWT},
	})
	security, _ := exchanged["access_token"].(string)

	for name, scope := range map[string]string{
		"absent":       "",
		"unrecognised": "read write",
	} {
		rr, body := postToken(t, partnerHandler, url.Values{
			"grant_type": {grantJWTBearer}, "assertion": {security},
			"client_id": {"mcptt_client"}, "scope": {scope},
		})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s scope: status = %d, want 400", name, rr.Code)
		}
		if body["error"] == nil {
			t.Fatalf("%s scope: no OAuth error in the response", name)
		}
	}
}

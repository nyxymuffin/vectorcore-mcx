package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// The conformant IdMS: the OpenID Connect profile of TS 33.180 Annex B /
// TS 24.482. Authorization code flow with mandatory PKCE (S256, clause
// B.4.2.2), password authentication of provisioned users ("3gpp:acr:password"
// is the mandatory-to-support ACR), the MC service scopes of table B.4.2.2-1,
// and refresh tokens (clause B.5). Tokens are ES256-signed JWS per Annex
// B.2, reusing the shim's signer and JWKS endpoint.
//
// Codes and refresh tokens are in-memory: they are short-lived session state,
// and a restart simply requires clients to re-authenticate.

// mcSupportedScopes are the scopes this deployment's resource servers
// actually serve (MCVideo is out of scope by decision).
var mcSupportedScopes = map[string]bool{
	"openid":                                 true,
	"3gpp:mc:ptt_service":                    true,
	"3gpp:mc:data_service":                   true,
	"3gpp:mc:ptt_key_management_service":     true,
	"3gpp:mc:data_key_management_service":    true,
	"3gpp:mc:ptt_config_management_service":  true,
	"3gpp:mc:data_config_management_service": true,
	"3gpp:mc:ptt_group_management_service":   true,
	"3gpp:mc:data_group_management_service":  true,
	"3gpp:mc:location_management_service":    true,
}

type authCode struct {
	mcpttID       string
	clientID      string
	redirectURI   string
	codeChallenge string
	scope         string
	expiresAt     time.Time
	used          bool
}

type refreshGrant struct {
	mcpttID   string
	clientID  string
	scope     string
	expiresAt time.Time
}

type oidcState struct {
	mu       sync.Mutex
	codes    map[string]*authCode
	refresh  map[string]*refreshGrant
	lastSwep time.Time
}

func newOIDCState() *oidcState {
	return &oidcState{codes: map[string]*authCode{}, refresh: map[string]*refreshGrant{}}
}

// sweep drops expired entries; called opportunistically under the lock.
func (o *oidcState) sweep(now time.Time) {
	if now.Sub(o.lastSwep) < time.Minute {
		return
	}
	o.lastSwep = now
	for k, c := range o.codes {
		if now.After(c.expiresAt) {
			delete(o.codes, k)
		}
	}
	for k, r := range o.refresh {
		if now.After(r.expiresAt) {
			delete(o.refresh, k)
		}
	}
}

func registerIDMSOIDC(mux chi.Router, s *Server) {
	mux.Get("/idms/authorize", s.handleOIDCAuthorizeForm)
	mux.Post("/idms/authorize", s.handleOIDCAuthorizeSubmit)
	mux.Post("/idms/token", s.handleOIDCToken)
	mux.Get("/idms/jwks.json", s.handleIDMSJWKS)
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("csprng unavailable: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) clientRegistered(clientID string) bool {
	for _, allowed := range s.cfg.IDMS.AllowedClientIDs {
		if strings.TrimSpace(allowed) == strings.TrimSpace(clientID) {
			return true
		}
	}
	return false
}

// validateAuthRequest checks the TS 33.180 clause B.4.2.2 required
// parameters. Errors that predate a trusted redirect URI are answered
// directly; later ones would be redirected per RFC 6749 (kept direct here for
// operator visibility - the client sees the HTTP error either way).
func (s *Server) validateAuthRequest(q url.Values) (string, error) {
	if q.Get("response_type") != "code" {
		return "", fmt.Errorf("response_type must be code")
	}
	clientID := q.Get("client_id")
	if !s.clientRegistered(clientID) {
		return "", fmt.Errorf("client_id %q is not registered", clientID)
	}
	redirectURI := q.Get("redirect_uri")
	if !s.redirectURIAllowed(redirectURI) {
		return "", fmt.Errorf("redirect_uri is not registered")
	}
	scope := q.Get("scope")
	if !strings.Contains(" "+scope+" ", " openid ") {
		return "", fmt.Errorf("scope must include openid")
	}
	if q.Get("state") == "" {
		return "", fmt.Errorf("state is required")
	}
	// PKCE is REQUIRED with S256 (clause B.4.2.2).
	if q.Get("code_challenge") == "" {
		return "", fmt.Errorf("code_challenge is required (PKCE)")
	}
	if q.Get("code_challenge_method") != "S256" {
		return "", fmt.Errorf("code_challenge_method must be S256")
	}
	return clientID, nil
}

// grantedScope intersects the requested scopes with what this deployment
// serves; openid always survives (it is mandatory in the request).
func grantedScope(requested string) string {
	var granted []string
	for _, sc := range strings.Fields(requested) {
		if mcSupportedScopes[sc] {
			granted = append(granted, sc)
		}
	}
	return strings.Join(granted, " ")
}

func (s *Server) handleOIDCAuthorizeForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if _, err := s.validateAuthRequest(q); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>VectorCore MCX Sign In</title></head>
<body style="font-family:sans-serif;max-width:22rem;margin:3rem auto">
<h1>MCX Sign In</h1>
<form method="post" action="/idms/authorize">
<input type="hidden" name="response_type" value="code">
<input type="hidden" name="client_id" value="%s">
<input type="hidden" name="redirect_uri" value="%s">
<input type="hidden" name="scope" value="%s">
<input type="hidden" name="state" value="%s">
<input type="hidden" name="code_challenge" value="%s">
<input type="hidden" name="code_challenge_method" value="S256">
<p><label>MC ID<br><input name="username" autocomplete="username" style="width:100%%"></label></p>
<p><label>Password<br><input type="password" name="password" autocomplete="current-password" style="width:100%%"></label></p>
<p><button type="submit">Sign in</button></p>
</form></body></html>`,
		html.EscapeString(q.Get("client_id")),
		html.EscapeString(q.Get("redirect_uri")),
		html.EscapeString(q.Get("scope")),
		html.EscapeString(q.Get("state")),
		html.EscapeString(q.Get("code_challenge")))
}

func (s *Server) handleOIDCAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientID, err := s.validateAuthRequest(r.Form)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Password authentication of the MC ID (TS 33.180 clause 5.1.2.1;
	// "3gpp:acr:password" is the mandatory-to-support method).
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	user, ok := s.authenticateMCID(r, username, password)
	if !ok {
		slog.Warn("IdMS authentication failed", "mc_id", username, "source", r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `<!doctype html><html><body style="font-family:sans-serif;margin:3rem"><h1>Sign in failed</h1><p>Unknown MC ID or wrong password.</p></body></html>`)
		return
	}

	mcpttID := strings.TrimSpace(user.MCPTTID)
	if mcpttID == "" {
		mcpttID = strings.TrimSpace(user.IMPU)
	}
	code := randomToken()
	now := time.Now()
	s.oidc.mu.Lock()
	s.oidc.sweep(now)
	s.oidc.codes[code] = &authCode{
		mcpttID:       mcpttID,
		clientID:      clientID,
		redirectURI:   r.Form.Get("redirect_uri"),
		codeChallenge: r.Form.Get("code_challenge"),
		scope:         grantedScope(r.Form.Get("scope")),
		expiresAt:     now.Add(60 * time.Second),
	}
	s.oidc.mu.Unlock()

	target, err := url.Parse(r.Form.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	query := target.Query()
	query.Set("code", code)
	query.Set("state", r.Form.Get("state"))
	target.RawQuery = query.Encode()
	slog.Info("IdMS authentication succeeded", "mc_id", username, "mcptt_id", mcpttID, "client_id", clientID)
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// authenticateMCID verifies MC ID + password against the provisioned users.
func (s *Server) authenticateMCID(r *http.Request, username, password string) (store.User, bool) {
	if username == "" || password == "" {
		return store.User{}, false
	}
	users, err := s.st.ListUsers(r.Context())
	if err != nil {
		return store.User{}, false
	}
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		mcID := strings.TrimSpace(user.MCID)
		if mcID == "" {
			mcID = strings.TrimSpace(user.MCPTTID)
		}
		if !strings.EqualFold(mcID, username) {
			continue
		}
		if store.VerifyPassword(user.PasswordHash, password) {
			return user, true
		}
		return store.User{}, false
	}
	return store.User{}, false
}

func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	if s.idmsSigner == nil {
		http.Error(w, "idms signer unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.tokenFromCode(w, r)
	case "refresh_token":
		s.tokenFromRefresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// tokenFromCode implements TS 33.180 clause B.4.2.4: code exchange with PKCE
// verification.
func (s *Server) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	verifier := r.Form.Get("code_verifier")

	now := time.Now()
	s.oidc.mu.Lock()
	grant, ok := s.oidc.codes[code]
	if ok {
		delete(s.oidc.codes, code) // single use, success or not
	}
	s.oidc.mu.Unlock()
	if !ok || grant.used || now.After(grant.expiresAt) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if grant.clientID != clientID || grant.redirectURI != r.Form.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// PKCE S256: BASE64URL(SHA256(code_verifier)) must equal the challenge.
	sum := sha256.Sum256([]byte(verifier))
	if verifier == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != grant.codeChallenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	s.issueTokens(w, grant.mcpttID, grant.clientID, grant.scope, true)
}

// tokenFromRefresh implements TS 33.180 clause B.5: the refresh token is
// rotated on use.
func (s *Server) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	token := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")
	now := time.Now()
	s.oidc.mu.Lock()
	grant, ok := s.oidc.refresh[token]
	if ok {
		delete(s.oidc.refresh, token)
	}
	s.oidc.mu.Unlock()
	if !ok || now.After(grant.expiresAt) || grant.clientID != clientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	scope := grant.scope
	if requested := r.Form.Get("scope"); requested != "" {
		// A refresh may narrow but never widen the scope (RFC 6749 §6).
		narrowed := grantedScope(requested)
		var kept []string
		for _, sc := range strings.Fields(narrowed) {
			if strings.Contains(" "+grant.scope+" ", " "+sc+" ") {
				kept = append(kept, sc)
			}
		}
		scope = strings.Join(kept, " ")
	}
	s.issueTokens(w, grant.mcpttID, grant.clientID, scope, false)
}

func (s *Server) issueTokens(w http.ResponseWriter, mcpttID, clientID, scope string, withIDToken bool) {
	now := time.Now()
	accessTTL := s.cfg.IDMS.AccessTokenTTLSeconds
	if accessTTL <= 0 {
		accessTTL = 3600
	}
	refreshTTL := s.cfg.IDMS.RefreshTokenTTLSeconds
	if refreshTTL <= 0 {
		refreshTTL = 30 * 24 * 3600
	}
	issuer := s.idmsIssuer()
	base := map[string]any{
		"iss":      issuer,
		"sub":      mcpttID,
		"mcptt_id": mcpttID,
		"iat":      now.Unix(),
		"exp":      now.Add(time.Duration(accessTTL) * time.Second).Unix(),
		"jti":      randomToken(),
	}
	accessClaims := cloneClaims(base)
	accessClaims["client_id"] = clientID
	accessClaims["scope"] = scope
	accessToken, err := s.idmsSigner.sign(accessClaims)
	if err != nil {
		http.Error(w, "token signing failed", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   accessTTL,
		"scope":        scope,
	}
	if withIDToken {
		idClaims := cloneClaims(base)
		idClaims["aud"] = clientID
		idClaims["azp"] = clientID
		idToken, err := s.idmsSigner.sign(idClaims)
		if err != nil {
			http.Error(w, "token signing failed", http.StatusInternalServerError)
			return
		}
		response["id_token"] = idToken
	}

	refreshToken := randomToken()
	s.oidc.mu.Lock()
	s.oidc.refresh[refreshToken] = &refreshGrant{
		mcpttID: mcpttID, clientID: clientID, scope: scope,
		expiresAt: now.Add(time.Duration(refreshTTL) * time.Second),
	}
	s.oidc.mu.Unlock()
	response["refresh_token"] = refreshToken

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
	slog.Info("IdMS tokens issued", "mcptt_id", mcpttID, "client_id", clientID, "scope", scope)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

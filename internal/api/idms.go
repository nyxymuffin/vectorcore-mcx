package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// The development identity shim.
//
// This is deliberately NOT an implementation of 3GPP TS 24.482. It performs no
// user authentication: any caller able to reach the token endpoint receives a
// token asserting a provisioned subscriber's MCPTT identity. It exists so a
// client that insists on an OIDC endpoint can be brought up on an isolated lab
// network, and it is registered only when explicitly enabled.
//
// What it does do correctly is issue a *signed* token. TS 33.180 Annex B.2.2.1
// requires the access token to carry a JWS, so an "alg":"none" token is not an
// incomplete implementation of the profile but a violation of it, and any
// conformant relying party must reject it.

// idmsSigner signs shim tokens with ES256.
type idmsSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newIDMSSigner(keyFile string) (*idmsSigner, error) {
	if strings.TrimSpace(keyFile) == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral signing key: %w", err)
		}
		return &idmsSigner{key: key, kid: keyID(&key.PublicKey)}, nil
	}

	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signing key %s is not PEM encoded", keyFile)
	}

	key, err := parseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key %s: %w", keyFile, err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signing key %s must use P-256 for ES256", keyFile)
	}
	return &idmsSigner{key: key, kid: keyID(&key.PublicKey)}, nil
}

func parseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an EC private key")
	}
	return key, nil
}

func keyID(pub *ecdsa.PublicKey) string {
	sum := sha256.Sum256(append(pad32(pub.X), pad32(pub.Y)...))
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func pad32(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

// sign produces a compact JWS with ES256. The signature is the raw r||s pair
// required by RFC 7518, not the ASN.1 form that crypto/ecdsa returns.
func (s *idmsSigner) sign(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "ES256", "typ": "JWT", "kid": s.kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	signature := append(pad32(r), pad32(sv)...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *idmsSigner) jwks() map[string]any {
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "EC",
			"crv": "P-256",
			"alg": "ES256",
			"use": "sig",
			"kid": s.kid,
			"x":   base64.RawURLEncoding.EncodeToString(pad32(s.key.PublicKey.X)),
			"y":   base64.RawURLEncoding.EncodeToString(pad32(s.key.PublicKey.Y)),
		}},
	}
}

func registerIDMSShim(mux chi.Router, s *Server) {
	mux.Get("/idms/authorize", s.handleIDMSAuthorize)
	mux.Get("/idms/stats", s.handleIDMSStats)
	mux.Post("/idms/token", s.handleIDMSToken)
	mux.Get("/idms/jwks.json", s.handleIDMSJWKS)
}

func (s *Server) idmsIssuer() string {
	if v := strings.TrimSpace(s.cfg.IDMS.Issuer); v != "" {
		return v
	}
	return "vectorcore-mcx-idms"
}

// redirectURIAllowed enforces the pre-registration requirement of TS 33.180
// Annex B.3. Without it redirect_uri is attacker-chosen, which turns the
// authorize endpoint into an open redirect that also leaks the code.
//
// An empty allow list permits nothing: failing closed is the only safe default
// for an endpoint that hands out credentials.
func (s *Server) redirectURIAllowed(candidate string) bool {
	for _, allowed := range s.cfg.IDMS.AllowedRedirectURIs {
		if strings.EqualFold(strings.TrimSpace(allowed), strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func (s *Server) handleIDMSAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	if !s.redirectURIAllowed(redirectURI) {
		slog.Warn("IDMS authorize refused unregistered redirect_uri",
			"redirect_uri", redirectURI, "source", r.RemoteAddr)
		http.Error(w, "redirect_uri is not registered", http.StatusBadRequest)
		return
	}

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Build the query through net/url so that a crafted state cannot inject
	// further parameters, which raw concatenation allowed.
	query := target.Query()
	query.Set("code", "vectorcore-dev-code")
	if state := r.URL.Query().Get("state"); state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()

	slog.Info("IDMS authorize shim",
		"client_id", r.URL.Query().Get("client_id"),
		"redirect_uri", redirectURI,
		"response_type", r.URL.Query().Get("response_type"),
		"source", r.RemoteAddr,
	)
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) handleIDMSStats(w http.ResponseWriter, r *http.Request) {
	slog.Info("IDMS callback shim",
		"has_code", r.URL.Query().Get("code") != "",
		"has_state", r.URL.Query().Get("state") != "",
		"source", r.RemoteAddr,
	)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>VectorCore MCX IdMS</title></head><body style="font-family:sans-serif;margin:2rem"><h1>Authentication complete</h1><p>You can return to the MCPTT client.</p></body></html>`)
}

func (s *Server) handleIDMSJWKS(w http.ResponseWriter, r *http.Request) {
	if s.idmsSigner == nil {
		http.Error(w, "idms signer unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_ = json.NewEncoder(w).Encode(s.idmsSigner.jwks())
}

func (s *Server) handleIDMSToken(w http.ResponseWriter, r *http.Request) {
	if s.idmsSigner == nil {
		http.Error(w, "idms signer unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientID := valueOrAPI(r.Form.Get("client_id"), "mcptt_client")
	mcpttID, mcpttSource, userCount, userErr := s.idmsMCPTTID(r)
	now := time.Now()
	issuer := s.idmsIssuer()

	// exp and iat are JSON numbers. TS 33.180 Annex B.2.1.1 defines them as
	// numeric dates, and emitting strings fails a strict validator outright.
	base := map[string]any{
		"iss":      issuer,
		"sub":      mcpttID,
		"mcptt_id": mcpttID,
		"iat":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
		"jti":      fmt.Sprintf("vectorcore-%d", now.UnixNano()),
	}

	// aud is required in the ID token (Annex B.2.1.2).
	idClaims := cloneClaims(base)
	idClaims["aud"] = clientID
	idClaims["azp"] = clientID

	// scope and client_id are required in the access token (Annex B.2.2.2).
	accessClaims := cloneClaims(base)
	accessClaims["client_id"] = clientID
	accessClaims["scope"] = "openid 3gpp:mc:ptt_service"

	idToken, err := s.idmsSigner.sign(idClaims)
	if err != nil {
		slog.Error("IDMS id_token signing failed", "err", err)
		http.Error(w, "token signing failed", http.StatusInternalServerError)
		return
	}
	accessToken, err := s.idmsSigner.sign(accessClaims)
	if err != nil {
		slog.Error("IDMS access_token signing failed", "err", err)
		http.Error(w, "token signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})

	slog.Info("IDMS token shim",
		"grant_type", r.Form.Get("grant_type"),
		"client_id", clientID,
		"mcptt_id", mcpttID,
		"identity_source", mcpttSource,
		"user_count", userCount,
		"user_error", userErr,
		"source", r.RemoteAddr,
	)
}

func cloneClaims(src map[string]any) map[string]any {
	out := make(map[string]any, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (s *Server) idmsMCPTTID(r *http.Request) (string, string, int, string) {
	// Try to identify the device by its source IP, populated from SIP SUBSCRIBE
	// Contact headers after the first successful registration cycle.
	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if sourceIP != "" {
		if mcpttID, err := s.st.GetMCPTTIDByUEIP(r.Context(), sourceIP); err == nil && mcpttID != "" {
			users, _ := s.st.ListUsers(r.Context())
			return mcpttID, "ue_contact_ip", len(users), ""
		}
	}

	// Fall back: return the first enabled user with a populated identity.
	// On a device's very first boot the IP→user mapping does not exist yet;
	// the mapping is built the moment the device sends its first SIP SUBSCRIBE,
	// so subsequent connections (after an app restart) resolve correctly.
	users, err := s.st.ListUsers(r.Context())
	if err == nil {
		for _, user := range users {
			if !user.Enabled {
				continue
			}
			if strings.TrimSpace(user.IMPU) != "" {
				return strings.TrimSpace(user.IMPU), "users.impu", len(users), ""
			}
			if strings.TrimSpace(user.MCPTTID) != "" {
				return strings.TrimSpace(user.MCPTTID), "users.mcptt_id", len(users), ""
			}
		}
	}
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	return valueOrAPI(s.cfg.MCX.DefaultUserIdentity, "sip:mcptt-user@"+s.cfg.IMS.Realm), "fallback", len(users), errText
}

func valueOrAPI(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

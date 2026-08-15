package api

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/mctoken"
)

// Inter-domain user service authorisation, TS 33.180 Annex B.7.
//
// A user authorised in this domain who needs services in a partner domain
// takes two steps. First this IdMS, acting as the primary, exchanges the
// user's access token for a security token addressed to the partner
// (clauses B.7.2 and B.7.3, the OAuth 2.0 token exchange grant). Then the
// partner IdMS accepts that security token as a JWT bearer assertion and
// returns its own access token (clauses B.7.4 and B.7.5, RFC 7523). This
// server implements both roles, because an MC domain is a partner to
// somebody else's primary.

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	grantJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	tokenTypeJWT       = "urn:ietf:params:oauth:token-type:jwt"
)

// securityTokenTTL is the lifetime of a security token. Clause B.8 wants a
// short-lived token; the example of clause B.7.3 uses ten minutes.
const securityTokenTTL = 600 * time.Second

// tokenFromExchange implements clauses B.7.2 and B.7.3: this IdMS is the
// user's primary, and mints a security token that the named partner IdMS
// can verify.
func (s *Server) tokenFromExchange(w http.ResponseWriter, r *http.Request) {
	resource := strings.TrimSpace(r.Form.Get("resource"))
	subjectToken := strings.TrimSpace(r.Form.Get("subject_token"))
	subjectType := strings.TrimSpace(r.Form.Get("subject_token_type"))

	if resource == "" || subjectToken == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// Table B.7.2-1 fixes the subject token type: the access token
	// obtained during authorisation is a JSON Web Token.
	if subjectType != tokenTypeJWT {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	claims, err := s.idmsSigner.verify(subjectToken, s.idmsIssuer(), time.Now())
	if err != nil {
		slog.Warn("token exchange refused", "err", err)
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	subject, _ := claims["sub"].(string)
	mcpttID, _ := claims["mcptt_id"].(string)
	if subject == "" {
		subject = mcpttID
	}
	if subject == "" {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	clientID, _ := claims["client_id"].(string)

	// Table B.8-1: the audience carries the client ID and the address of
	// the target IdMS, which is the resource named in the request.
	now := time.Now()
	audience := []string{resource}
	if clientID != "" {
		audience = append([]string{clientID}, resource)
	}
	securityToken, err := s.idmsSigner.sign(map[string]any{
		"iss":      s.idmsIssuer(),
		"sub":      subject,
		"mcptt_id": mcpttID,
		"aud":      audience,
		"iat":      now.Unix(),
		"exp":      now.Add(securityTokenTTL).Unix(),
		"jti":      randomToken(),
	})
	if err != nil {
		http.Error(w, "token signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      securityToken,
		"issued_token_type": tokenTypeJWT,
		"token_type":        "Bearer",
		"expires_in":        int(securityTokenTTL.Seconds()),
	})
	slog.Info("IdMS security token issued", "sub", subject, "resource", resource)
}

// tokenFromAssertion implements clauses B.7.4 and B.7.5: this IdMS is the
// partner, and exchanges a security token minted by a trusted primary for
// its own access token.
func (s *Server) tokenFromAssertion(w http.ResponseWriter, r *http.Request) {
	assertion := strings.TrimSpace(r.Form.Get("assertion"))
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	scope := r.Form.Get("scope")

	if assertion == "" || clientID == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !s.clientRegistered(clientID) {
		oauthError(w, http.StatusBadRequest, "invalid_client")
		return
	}

	claims, issuer, err := s.verifyPartnerAssertion(assertion)
	if err != nil {
		// Clause B.7.4: authentication of the security token is required
		// before it can be exchanged.
		slog.Warn("partner assertion refused", "err", err)
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !audienceAccepts(claims["aud"], s.idmsIssuer()) {
		slog.Warn("partner assertion is addressed elsewhere", "issuer", issuer)
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	subject, _ := claims["sub"].(string)
	if strings.TrimSpace(subject) == "" {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	// Clause B.9: the access token issued for partner services is an
	// ordinary access token of clause B.2.2, so it is minted the same way
	// a locally authorised user's is.
	s.issueTokens(w, subject, clientID, grantedScope(scope), false)
	slog.Info("IdMS partner access token issued", "sub", subject, "primary", issuer)
}

// verifyPartnerAssertion checks a security token against every configured
// partner IdMS, returning the claims and the issuer that accepted it.
func (s *Server) verifyPartnerAssertion(assertion string) (map[string]any, string, error) {
	if len(s.partnerIdMS) == 0 {
		return nil, "", fmt.Errorf("no partner IdM services are configured")
	}
	for issuer, validator := range s.partnerIdMS {
		claims, err := validator.ValidateClaims(assertion)
		if err == nil {
			return claims, issuer, nil
		}
	}
	return nil, "", fmt.Errorf("the assertion does not verify against any configured partner")
}

// audienceAccepts reports whether the aud claim, which JWT allows to be a
// string or an array of strings, names this server.
func audienceAccepts(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// verify checks a token this server signed and returns its claims. It is
// the counterpart of sign, used where the IdMS has to consume its own
// output: the token exchange of clause B.7.2 takes the access token this
// server issued moments earlier.
func (s *idmsSigner) verify(token, issuer string, now time.Time) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token is not a compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("token alg %q is not accepted", header.Alg)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return nil, fmt.Errorf("token signature is not the 64 byte r||s form")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	sv := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(&s.key.PublicKey, digest[:], r, sv) {
		return nil, fmt.Errorf("token was not signed by this IdM server")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}
	exp, _ := claims["exp"].(float64)
	if exp == 0 || now.After(time.Unix(int64(exp), 0)) {
		return nil, fmt.Errorf("token is expired or carries no expiry")
	}
	if iss, _ := claims["iss"].(string); issuer != "" && iss != issuer {
		return nil, fmt.Errorf("token issuer %q is not this IdM server", iss)
	}
	return claims, nil
}

// loadPartnerIdMS builds a validator per configured partner IdM service.
// A partner whose JWKS cannot be read is reported and skipped rather than
// preventing the server from starting: local authorisation must keep
// working when a federation partner is misconfigured.
func loadPartnerIdMS(partners []config.PartnerIdMS) map[string]*mctoken.Validator {
	out := map[string]*mctoken.Validator{}
	for _, p := range partners {
		issuer := strings.TrimSpace(p.Issuer)
		if issuer == "" || strings.TrimSpace(p.JWKSFile) == "" {
			slog.Error("partner IdM service needs both an issuer and a JWKS file", "issuer", issuer)
			continue
		}
		validator, err := mctoken.New(p.JWKSFile, issuer)
		if err != nil {
			slog.Error("partner IdM service unavailable", "issuer", issuer, "err", err)
			continue
		}
		out[issuer] = validator
	}
	return out
}

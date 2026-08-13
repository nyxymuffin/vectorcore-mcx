package sip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// Service authorization per TS 33.180 clause 5.1.3.2.3: the client's SIP
// PUBLISH carries an access token in the mcptt-info MIME body, and the server
// validates it before binding the asserted MCPTT identity.
//
// The verifier below accepts ES256 only. Anything else - and "none" above all
// else - is rejected outright: the algorithm list is the server's choice, not
// the token's.

// tokenValidator verifies compact JWS access tokens against a JWKS.
type tokenValidator struct {
	keys   map[string]*ecdsa.PublicKey // kid → key
	issuer string
	now    func() time.Time
}

type jwksDocument struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Kid string `json:"kid"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

// newTokenValidator loads a JWKS file of P-256 keys. Keys of other types are
// skipped rather than failing the load, so one RSA entry in a shared JWKS does
// not disable service authorization, but a file yielding no usable key is an
// error: a validator that can verify nothing rejects everyone.
func newTokenValidator(jwksFile, issuer string) (*tokenValidator, error) {
	raw, err := os.ReadFile(jwksFile)
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}
	var doc jwksDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			continue
		}
		keys[k.Kid] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS %s contains no usable P-256 keys", jwksFile)
	}
	return &tokenValidator{keys: keys, issuer: issuer, now: time.Now}, nil
}

// validate checks the token and returns its mcptt_id claim.
func (v *tokenValidator) validate(token string) (string, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token is not a compact JWS")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("token header: %w", err)
	}
	// The allowed algorithm is fixed server-side. Honouring the token's own
	// header is exactly the alg:none / key-confusion mistake.
	if header.Alg != "ES256" {
		return "", fmt.Errorf("token alg %q is not accepted (want ES256)", header.Alg)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return "", fmt.Errorf("token signature is not the 64 byte r||s form")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	sv := new(big.Int).SetBytes(signature[32:])

	if !v.verifyWithAnyKey(header.Kid, digest[:], r, sv) {
		return "", fmt.Errorf("token signature does not verify against any trusted key")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("token claims: %w", err)
	}
	var claims struct {
		Iss     string  `json:"iss"`
		Exp     float64 `json:"exp"`
		MCPTTID string  `json:"mcptt_id"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", fmt.Errorf("token claims: %w", err)
	}

	if claims.Exp == 0 || v.now().After(time.Unix(int64(claims.Exp), 0)) {
		return "", fmt.Errorf("token is expired or carries no expiry")
	}
	if v.issuer != "" && claims.Iss != v.issuer {
		return "", fmt.Errorf("token issuer %q is not trusted", claims.Iss)
	}
	if strings.TrimSpace(claims.MCPTTID) == "" {
		return "", fmt.Errorf("token carries no mcptt_id claim")
	}
	return strings.TrimSpace(claims.MCPTTID), nil
}

// verifyWithAnyKey tries the kid-matched key first and falls back to every
// trusted key, so a rotated JWKS keeps verifying tokens minted moments before
// the rotation.
func (v *tokenValidator) verifyWithAnyKey(kid string, digest []byte, r, s *big.Int) bool {
	if key, ok := v.keys[kid]; ok && ecdsa.Verify(key, digest, r, s) {
		return true
	}
	for id, key := range v.keys {
		if id == kid {
			continue
		}
		if ecdsa.Verify(key, digest, r, s) {
			return true
		}
	}
	return false
}

// accessTokenFromPublish extracts the access token from the mcptt-info body of
// a service-authorization PUBLISH (TS 24.379 clause 7.3.3): the
// <mcptt-access-token> element, or failing that any mcpttString whose shape is
// a compact JWS - the same shape mcpttIdentityFromBody deliberately skips.
func accessTokenFromPublish(msg *Message) string {
	body := msg.Body
	if part := msg.Part("application/vnd.3gpp.mcptt-info+xml"); part != nil {
		body = part.Body
	}
	text := string(body)

	if tokenBody := xmlElementBody(text, "mcptt-access-token"); tokenBody != "" {
		if v := xmlElementText(tokenBody, "mcpttString"); v != "" {
			return v
		}
		if v := strings.TrimSpace(tokenBody); looksLikeJWT(v) {
			return v
		}
	}
	if v := xmlElementText(text, "mcpttString"); looksLikeJWT(v) {
		return v
	}
	return ""
}

// serviceAuthWarning is the Warning header of TS 24.379 clause 4.4.2 for a
// failed service authorization.
func (s *Server) serviceAuthWarning() header {
	return header{"Warning", fmt.Sprintf("399 %s \"101 service authorisation failed\"", advertiseHostOnly(s.cfg))}
}

// authorizeServicePublish validates the access token of a service
// authorization PUBLISH and returns the authenticated MCPTT identity.
func (s *Server) authorizeServicePublish(msg *Message) (string, error) {
	if s.authTokens == nil {
		return "", fmt.Errorf("token validator unavailable")
	}
	token := accessTokenFromPublish(msg)
	if token == "" {
		return "", fmt.Errorf("no access token in the PUBLISH body")
	}
	return s.authTokens.validate(token)
}

package sip

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/svinson1121/vectorcore-mcx/internal/mctoken"
)

// Service authorization per TS 33.180 clause 5.1.3.2.3: the client's SIP
// PUBLISH carries an access token in the mcptt-info MIME body, and the server
// validates it before binding the asserted MCPTT identity.
//
// The verifier below accepts ES256 only. Anything else - and "none" above all
// else - is rejected outright: the algorithm list is the server's choice, not
// the token's.

// tokenValidator is the shared MC access token validator (internal/mctoken).
type tokenValidator = mctoken.Validator

func newTokenValidator(jwksFile, issuer string) (*tokenValidator, error) {
	return mctoken.New(jwksFile, issuer)
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

// mcpttWarning builds a Warning header carrying a TS 24.379 clause 4.4.2
// warning text, e.g. "120 user is not affiliated to this group".
func (s *Server) mcpttWarning(text string) header {
	return header{"Warning", fmt.Sprintf("399 %s %q", advertiseHostOnly(s.cfg), text)}
}

// serviceAuthWarning is the Warning header of TS 24.379 clause 4.4.2 for a
// failed service authorization.
func (s *Server) serviceAuthWarning() header {
	return s.mcpttWarning("101 service authorisation failed")
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
	return s.authTokens.Validate(token)
}

// mcpttIDFromThirdPartyRegister identifies the MCPTT ID from a third-party
// REGISTER (TS 24.379 clause 7.3.2): the client's original REGISTER travels
// in the message/sip MIME body, and its mcptt-info body carries the access
// token whose mcptt_id claim is the identity to bind (clause 7.3.1A,
// unprotected case). Returns empty when no binding can be made: absent body,
// absent token, failed validation, or no validator configured - binding an
// identity nobody authenticated would defeat the point of the procedure.
func (s *Server) mcpttIDFromThirdPartyRegister(msg *Message) string {
	part := msg.Part("message/sip")
	if part == nil {
		return ""
	}
	inner, err := Parse(part.Body)
	if err != nil {
		slog.Debug("third-party REGISTER inner request unparseable", "err", err)
		return ""
	}
	token := accessTokenFromPublish(inner)
	if token == "" {
		slog.Debug("third-party REGISTER carried no access token; no MCPTT ID bound")
		return ""
	}
	if s.authTokens == nil {
		slog.Warn("third-party REGISTER carried an access token but sip.auth is not configured; refusing to bind an unvalidated identity")
		return ""
	}
	mcpttID, err := s.authTokens.Validate(token)
	if err != nil {
		slog.Warn("third-party REGISTER service authorization failed", "err", err)
		return ""
	}
	return mcpttID
}

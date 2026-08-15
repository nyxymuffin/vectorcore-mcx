package sip

import (
	"context"
	"strings"
)

// Answer-mode determination for the terminating participating function
// (TS 24.379 clause 10.1.1.3.2 steps 3, 7 and 8).
//
// The Answer-Mode Indication is carried in the application/poc-settings+xml
// event package the client PUBLISHes (clauses 7.3.3/7.3.4): per RFC 4354 the
// <am-settings> element contains an <answer-mode> element whose value is
// "automatic" or "manual". Note the divergence in vocabulary: 24.379 calls
// the two indications "auto-answer" and "manual-answer", but the wire values
// RFC 4354 defines are "automatic" and "manual"; both spellings are accepted
// here because clients following the 3GPP prose alone have been seen to emit
// the latter forms.

type answerMode int

const (
	answerModeUnknown answerMode = iota
	answerModeAutomatic
	answerModeManual
)

// answerModeFor returns the served user's current Answer-Mode Indication from
// their stored poc-settings publication. answerModeUnknown means the client
// has never published usable settings, in which case clause 10.1.1.3.2 step 3
// forbids inviting them (480 with warning "146 T-PF unable to determine the
// service settings for the called user").
func (s *Server) answerModeFor(ctx context.Context, userURI string) answerMode {
	if s.st == nil {
		return answerModeUnknown
	}
	state, err := s.st.GetPublishedState(ctx, userURI, "poc-settings")
	if err != nil || state == nil {
		return answerModeUnknown
	}
	return parseAnswerMode(state.Body)
}

// parseAnswerMode extracts the <answer-mode> value from a poc-settings body,
// which may arrive bare or as part of a multipart PUBLISH stored verbatim.
func parseAnswerMode(body string) answerMode {
	settings := xmlElementBody(body, "am-settings")
	if settings == "" {
		return answerModeUnknown
	}
	value := strings.ToLower(xmlElementText(settings, "answer-mode"))
	if value == "" {
		// Defensive: some clients place the value directly in <am-settings>.
		value = strings.ToLower(strings.TrimSpace(settings))
	}
	switch {
	case strings.Contains(value, "automatic"), strings.Contains(value, "auto-answer"):
		return answerModeAutomatic
	case strings.Contains(value, "manual"):
		return answerModeManual
	}
	return answerModeUnknown
}

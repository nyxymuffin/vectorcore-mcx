package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// First-to-answer call with floor control, TS 24.379 clause 11.1.1: the
// caller lists several candidates in the resource-lists body; every candidate
// is invited in parallel with Priv-Answer-Mode: Manual (clause 11.1.1.4.1
// step 3), the first 200 wins, the caller's 200 names the winner in
// <mcptt-called-party-id>, and the other legs are released with
// <release-reason> "not selected for call" (clause 11.1.1.4.2 step 8).

// ftaCandidate is one invited leg of a first-to-answer race.
type ftaCandidate struct {
	member    string
	legCallID string
	done      chan bool
}

// ftaOutcome is one leg's result in the race.
type ftaOutcome struct {
	candidate *ftaCandidate
	ok        bool
}

func (s *Server) handleFirstToAnswerInvite(ctx context.Context, send responder, msg *Message, source, transport string) {
	localTag := newToken()
	callID := msg.Header("Call-ID")
	initiatorURI := identityFrom(msg)

	if !s.servedUserExists(ctx, initiatorURI) {
		s.respond(send, msg, 404, "Not Found",
			[]header{s.mcpttWarning("141 user unknown to the participating function")}, nil)
		return
	}

	// Clause 11.1.1.4.2 step 3: no resource-lists body means the called
	// parties cannot be determined. (Unlike "private", several entries are
	// the point.)
	entries := resourceListEntries(msg)
	if len(entries) == 0 {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("145 unable to determine called party")}, nil)
		return
	}

	offer, _ := s.sdpOffer(msg)
	sdpInfo := parseSDP(offer)

	if _, err := s.st.CreateDialog(ctx, store.Dialog{
		CallID:       callID,
		LocalTag:     localTag,
		RemoteTag:    tagFrom(msg.Header("From")),
		FromURI:      identityFromHeader(msg.Header("From")),
		ToURI:        identityFromHeader(msg.Header("To")),
		RequestURI:   msg.URI,
		IMPU:         identityFromHeader(msg.Header("From")),
		Method:       "INVITE",
		State:        "confirmed",
		RemoteTarget: uriFromHeader(msg.Header("Contact")),
		LocalCSeq:    1,
		RemoteCSeq:   cseqNumber(msg.Header("CSeq")),
		LastMethod:   "INVITE",
		LastStatus:   200,
		Transport:    transport,
		SourceAddr:   source,
		TopVia:       msg.Header("Via"),
	}); err != nil {
		slog.Warn("first-to-answer dialog store failed", "err", err, "call_id", callID)
	}

	slog.Info("MCPTT first-to-answer INVITE",
		"call_id", callID, "initiator", initiatorURI, "candidates", len(entries), "source", source)

	s.uasInvites.Store(callID, &uasInviteState{msg: msg, send: send, tag: localTag})
	s.respond(send, msg, 100, "Trying", nil, nil)

	// Clause 11.1.1.4.2 step 11: session identity at session creation; it is
	// also the leg-correlation key for the media relay, like private calls.
	sessionURI := s.allocateSessionIdentity(callID)

	body, _ := s.sdpAnswer(msg)
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:               callID,
		State:                "ringing",
		InitiatorURI:         initiatorURI,
		GroupURI:             sessionURI,
		LocalTag:             localTag,
		RemoteTag:            tagFrom(msg.Header("From")),
		Transport:            transport,
		SourceAddr:           source,
		AudioIP:              sdpInfo.Audio.ConnectionIP,
		AudioPort:            sdpInfo.Audio.Port,
		AudioProto:           sdpInfo.Audio.Proto,
		AudioPayloads:        sdpInfo.Audio.Payloads,
		FloorControlIP:       sdpInfo.FloorControl.ConnectionIP,
		FloorControlPort:     sdpInfo.FloorControl.Port,
		FloorControlProto:    sdpInfo.FloorControl.Proto,
		FloorControlPayloads: sdpInfo.FloorControl.Payloads,
		SDPOffer:             offer,
		SDPAnswer:            string(body),
	}); err != nil {
		slog.Warn("first-to-answer call store failed", "err", err, "call_id", callID)
	}

	audioPayload := "114 96 9 0 8"
	if len(sdpInfo.Audio.Payloads) > 0 {
		audioPayload = strings.Join(sdpInfo.Audio.Payloads, " ")
	}

	// Clause 11.1.1.4.2 step 12: invite every listed candidate per
	// 11.1.1.4.1. Candidates without a served-user binding or a registration
	// are skipped rather than failing the whole race; poc-settings gating
	// does not apply since the leg forces Priv-Answer-Mode: Manual.
	users, _ := s.st.ListUsers(ctx)
	regs, _ := s.st.ListRegistrations(ctx)
	var candidates []*ftaCandidate
	for _, member := range entries {
		member = strings.TrimSpace(member)
		impu := ""
		for _, user := range users {
			if !user.Enabled {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(user.MCPTTID), member) ||
				strings.EqualFold(strings.TrimSpace(user.IMPU), member) {
				impu = strings.TrimSpace(user.IMPU)
				if impu == "" {
					impu = strings.TrimSpace(user.MCPTTID)
				}
				break
			}
		}
		if impu == "" {
			slog.Info("first-to-answer candidate skipped: not a served user", "member", member)
			continue
		}
		var reg *store.Registration
		for _, r := range regs {
			if r.Registered && strings.EqualFold(strings.TrimSpace(r.PublicIdentity), impu) {
				candidate := r
				reg = &candidate
				break
			}
		}
		if reg == nil {
			slog.Info("first-to-answer candidate skipped: not registered", "member", member)
			continue
		}
		done := make(chan bool, 1)
		legCallID := s.sendRXInvite(ctx, callID, sessionURI, initiatorURI, impu, audioPayload, "first-to-answer", *reg, answerModeManual, done)
		if legCallID == "" {
			continue
		}
		candidates = append(candidates, &ftaCandidate{member: impu, legCallID: legCallID, done: done})
	}
	if len(candidates) == 0 {
		s.uasInvites.Delete(callID)
		s.respondTagged(send, msg, 403, "Forbidden", localTag,
			[]header{s.mcpttWarning("145 unable to determine called party")}, nil)
		return
	}

	s.respondTagged(send, msg, 180, "Ringing", localTag,
		inviteResponseHeaders(s.advertisedSIPURI(transport), s.recordRouteURI(transport), msg.HeadersFor("Record-Route"), ""), nil)

	// The race: first established leg wins. Outcomes are funnelled into one
	// channel so late answers are still observed for loser cleanup.
	outcomes := make(chan ftaOutcome, len(candidates))
	for _, c := range candidates {
		c := c
		go func() {
			ok := <-c.done
			outcomes <- ftaOutcome{candidate: c, ok: ok}
		}()
	}

	var winner *ftaCandidate
	pending := len(candidates)
	timer := time.NewTimer(privateAnswerWait)
	defer timer.Stop()
	for winner == nil && pending > 0 {
		select {
		case outcome := <-outcomes:
			pending--
			if outcome.ok {
				winner = outcome.candidate
			}
		case <-timer.C:
			pending = 0
		case <-ctx.Done():
			return
		}
	}

	if winner == nil {
		slog.Info("MCPTT first-to-answer: no candidate answered", "call_id", callID)
		if err := s.st.UpdateCallState(ctx, callID, "terminated"); err != nil {
			slog.Warn("first-to-answer state update failed", "err", err, "call_id", callID)
		}
		s.uasInvites.Delete(callID)
		s.respondTagged(send, msg, 480, "Temporarily Unavailable", localTag, nil, nil)
		return
	}

	slog.Info("MCPTT first-to-answer winner", "call_id", callID, "winner", winner.member)
	if err := s.st.UpdateCallState(ctx, callID, "answered"); err != nil {
		slog.Warn("first-to-answer state update failed", "err", err, "call_id", callID)
	}

	// Clause 11.1.1.4.2 step 8: the losers. Already-established legs get a
	// BYE with <release-reason> "not selected for call"; legs that answer
	// after the winner get the same the moment their outcome lands. (A true
	// CANCEL toward still-ringing losers is deferred - the unanswered leg
	// simply times out and the late-answer BYE covers the 8 d fallback.)
	go s.releaseFTALosers(candidates, winner, pending, outcomes)

	// The winner's 200 toward the caller (clause 11.1.1.4.2, first-to-answer
	// 200 handling step 5: mcptt-called-party-id names the answered party).
	infoBody := fmt.Sprintf(
		`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
			`<mcptt-called-party-id><mcpttURI>%s</mcpttURI></mcptt-called-party-id>`+
			`<session-type>first-to-answer</session-type>`+
			`</mcptt-Params></mcpttinfo>`, winner.member)
	const boundary = "mcxasfta"
	multipart := fmt.Sprintf(
		"--%s\r\nContent-Type: application/sdp\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n%s\r\n--%s--\r\n",
		boundary, string(body), boundary, infoBody, boundary)

	headers := []header{
		{"Contact", fmt.Sprintf("<%s>;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mcptt\";isfocus", sessionURI)},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"Session-Expires", "1800;refresher=uac"},
		{"Require", "timer"},
		{"Supported", "tdialog, norefersub, explicitsub, nosub"},
		{"Allow", allowValue},
		{"Content-Type", fmt.Sprintf(`multipart/mixed;boundary="%s"`, boundary)},
	}
	headers = append(recordRouteHeaders(s.recordRouteURI(transport), msg.HeadersFor("Record-Route")), headers...)
	s.markSessionAnswered(ctx, callID)
	s.uasInvites.Delete(callID)
	s.respondTagged(send, msg, 200, "OK", localTag, headers, []byte(multipart))
}

// releaseFTALosers sends the "not selected for call" BYE to every candidate
// other than the winner whose leg established - both those already up when
// the winner answered and those whose late answers arrive afterwards.
func (s *Server) releaseFTALosers(candidates []*ftaCandidate, winner *ftaCandidate, pending int, outcomes chan ftaOutcome) {
	ctx := context.Background()
	release := func(c *ftaCandidate) {
		call, err := s.st.GetCall(ctx, c.legCallID)
		if err != nil || call == nil {
			return
		}
		if call.State == "terminated" || call.State == "cancelled" {
			return
		}
		s.sendRXBYEWithReason(ctx, *call, "not selected for call")
	}
	// Legs already established before the winner.
	for _, c := range candidates {
		if c != winner {
			release(c)
		}
	}
	// Late answers within the leg answer window.
	deadline := time.NewTimer(privateAnswerWait)
	defer deadline.Stop()
	for pending > 0 {
		select {
		case outcome := <-outcomes:
			pending--
			if outcome.ok && outcome.candidate != winner {
				release(outcome.candidate)
			}
		case <-deadline.C:
			return
		}
	}
}

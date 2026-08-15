package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Private call with floor control, TS 24.379 clause 11.1.1: the callee
// arrives in an application/resource-lists+xml body of the INVITE whose
// mcptt-info carries <session-type>private</session-type>. The controlling
// function invites the callee (clause 11.1.1.4.1) and answers the caller only
// after the callee's own 200 (clause 11.1.1.4.2, "Upon receiving a SIP 200
// (OK) response ... shall generate a SIP 200 (OK) response") — unlike the
// group flow, which answers as the focus once member invitations are on the
// wire. First-to-answer calls (parallel dialogs racing to answer, with CANCEL
// of the losers) are not implemented and take the pre-existing path.

// privateAnswerWait bounds how long the caller leg waits for the callee's
// final response before answering 480; the callee leg's own timer runs
// slightly longer so its outcome always arrives first.
const privateAnswerWait = 32 * time.Second

func (s *Server) handlePrivateInvite(ctx context.Context, send responder, msg *Message, source, transport string) {
	localTag := newToken()
	callID := msg.Header("Call-ID")
	initiatorURI := identityFrom(msg)

	// Originating participating check (clause 10.1.1.3.1.1 steps 2/2a).
	if !s.servedUserExists(ctx, initiatorURI) {
		slog.Warn("MCPTT private INVITE from unknown user rejected",
			"call_id", callID, "initiator", initiatorURI,
			"warning", "141 user unknown to the participating function")
		s.respond(send, msg, 404, "Not Found",
			[]header{s.mcpttWarning("141 user unknown to the participating function")}, nil)
		return
	}

	// Clause 11.1.1.4.2 steps 3 and 4: exactly one callee in the
	// resource-lists body; anything else means the called party cannot be
	// determined.
	entries := resourceListEntries(msg)
	if len(entries) != 1 {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("145 unable to determine called party")}, nil)
		return
	}
	callee := strings.TrimSpace(entries[0])

	// Clause 11.1.1.3.2 step 7: without a binding between the callee's MCPTT
	// ID and a registered public user identity the call is a 404.
	calleeImpu := ""
	if users, err := s.st.ListUsers(ctx); err == nil {
		for _, user := range users {
			if !user.Enabled {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(user.MCPTTID), callee) ||
				strings.EqualFold(strings.TrimSpace(user.IMPU), callee) {
				calleeImpu = strings.TrimSpace(user.IMPU)
				if calleeImpu == "" {
					calleeImpu = strings.TrimSpace(user.MCPTTID)
				}
				break
			}
		}
	}
	var calleeReg *store.Registration
	if calleeImpu != "" {
		regs, err := s.st.ListRegistrations(ctx)
		if err == nil {
			for _, r := range regs {
				if r.Registered && strings.EqualFold(strings.TrimSpace(r.PublicIdentity), calleeImpu) {
					reg := r
					calleeReg = &reg
					break
				}
			}
		}
	}
	if calleeImpu == "" || calleeReg == nil {
		slog.Info("MCPTT private call: callee not bound/registered",
			"call_id", callID, "callee", callee)
		s.respond(send, msg, 404, "Not Found", nil, nil)
		return
	}

	// Clause 11.1.1.3.2 step 7a: no Answer-Mode Indication from the callee
	// means 480 with warning "146".
	mode := s.answerModeFor(ctx, calleeImpu)
	if mode == answerModeUnknown {
		s.respond(send, msg, 480, "Temporarily Unavailable",
			[]header{s.mcpttWarning("146 T-PF unable to determine the service settings for the called user")}, nil)
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
		MCPTTID:      callee,
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
		slog.Warn("private dialog store failed", "err", err, "call_id", callID)
	}

	slog.Info("MCPTT private INVITE",
		"call_id", callID, "initiator", initiatorURI, "callee", callee, "source", source)

	s.uasInvites.Store(callID, &uasInviteState{msg: msg, send: send, tag: localTag})
	s.respond(send, msg, 100, "Trying", nil, nil)

	// Clause 11.1.1.4.2 step 11: session identity at session creation. The
	// session identity doubles as the correlation key of the two legs, so the
	// media relay pairs them the same way it pairs group legs.
	sessionURI := s.allocateSessionIdentity(callID)

	body, _ := s.sdpAnswer(msg)
	now := time.Now().UTC()
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:               callID,
		State:                "ringing",
		InitiatorURI:         initiatorURI,
		TargetURI:            callee,
		GroupURI:             sessionURI,
		MCPTTID:              callee,
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
		slog.Warn("private call store failed", "err", err, "call_id", callID)
	}

	audioPayload := "114 96 9 0 8"
	if len(sdpInfo.Audio.Payloads) > 0 {
		audioPayload = strings.Join(sdpInfo.Audio.Payloads, " ")
	}

	// Clause 11.1.1.4.2 step 13: invite the callee per 11.1.1.4.1. The done
	// channel carries the callee leg's outcome back to this flow.
	done := make(chan bool, 1)
	s.sendRXInvite(ctx, callID, sessionURI, initiatorURI, calleeImpu, audioPayload, "private", *calleeReg, mode, done)

	// The callee is ringing; tell the caller (the 180 forwarding rule of
	// clause 11.1.1.4.2, asserted locally as this server does not forward
	// individual provisionals).
	s.respondTagged(send, msg, 180, "Ringing", localTag,
		inviteResponseHeaders(s.advertisedSIPURI(transport), s.recordRouteURI(transport), msg.HeadersFor("Record-Route"), ""), nil)

	established := false
	timer := time.NewTimer(privateAnswerWait)
	defer timer.Stop()
	select {
	case established = <-done:
	case <-timer.C:
	case <-ctx.Done():
		return
	}

	if !established {
		slog.Info("MCPTT private call not answered", "call_id", callID, "callee", callee)
		if err := s.st.UpdateCallState(ctx, callID, "terminated"); err != nil {
			slog.Warn("private call state update failed", "err", err, "call_id", callID)
		}
		s.uasInvites.Delete(callID)
		s.respondTagged(send, msg, 480, "Temporarily Unavailable", localTag, nil, nil)
		return
	}

	if err := s.st.UpdateCallState(ctx, callID, "answered"); err != nil {
		slog.Warn("private call state update failed", "err", err, "call_id", callID)
	}
	if sdpGrantsImplicitFloor(body) {
		if _, err := s.st.UpdateCallFloorState(ctx, callID, store.FloorStateUpdate{
			State: "granted", Event: "sdp_granted", Subtype: 1, At: now,
		}); err != nil {
			slog.Warn("private floor grant store failed", "err", err, "call_id", callID)
		}
	}

	// Clause 11.1.1.4.2, on the callee's 200: answer the caller per
	// 6.3.3.2.3.2 with the SDP answer per 6.3.3.2.1.
	headers := []header{
		{"Contact", fmt.Sprintf("<%s>;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mcptt\";isfocus", sessionURI)},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"Session-Expires", "1800;refresher=uac"},
		{"Require", "timer"},
		{"Supported", "tdialog, norefersub, explicitsub, nosub"},
		{"Allow", allowValue},
		{"Content-Type", "application/sdp"},
	}
	headers = append(recordRouteHeaders(s.recordRouteURI(transport), msg.HeadersFor("Record-Route")), headers...)
	s.markSessionAnswered(ctx, callID)
	s.uasInvites.Delete(callID)
	s.respondTagged(send, msg, 200, "OK", localTag, headers, body)
}

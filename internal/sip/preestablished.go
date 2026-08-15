package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Pre-established sessions, TS 24.379 clause 8: a client sets up media with
// the participating function ahead of any call (clause 8.2.2), then
// originates calls over it with SIP REFER (clause 10.1.1.3.1.2) - the media
// and floor channel negotiated at establishment are reused, so call setup
// carries no SDP exchange. Session release is a plain BYE (clause 8.4).
//
// The resource-sharing binding of clause 8.2.2 steps 3-5 (Feature-Caps
// +g.3gpp.registration-token from the SIP core) requires core support that a
// standalone deployment does not have; establishment is instead gated on
// sip.preestablished.enabled with the local-policy authorisation of step 2.

// pesSession is one established pre-established session.
type pesSession struct {
	uri      string
	owner    string
	sdp      sdpInfo
	offer    string
	answer   string
	localTag string
}

// preEstablishedPSI is the public service identity clients INVITE to
// establish a pre-established session (clause 8.2.1).
func (s *Server) preEstablishedPSI() string {
	if v := strings.TrimSpace(s.cfg.SIP.PreEstablished.PSI); v != "" {
		return v
	}
	return "sip:mcptt-pes@" + s.cfg.IMS.Realm
}

// isPreEstablishedInvite recognises the establishment INVITE by its
// Request-URI: an exact match on the configured PSI, or - when the PSI is
// derived - a match on the PSI's user part so deployments reach it under
// whichever domain routes to this server.
func (s *Server) isPreEstablishedInvite(msg *Message) bool {
	if !s.cfg.SIP.PreEstablished.Enabled {
		return false
	}
	uri := strings.TrimSpace(msg.URI)
	psi := s.preEstablishedPSI()
	if strings.EqualFold(uri, psi) {
		return true
	}
	if strings.TrimSpace(s.cfg.SIP.PreEstablished.PSI) != "" {
		return false // an explicit PSI is matched exactly
	}
	return strings.EqualFold(sipURIUser(uri), sipURIUser(psi))
}

// sipURIUser returns the user part of a SIP URI.
func sipURIUser(uri string) string {
	uri = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(uri)), "sips:")
	uri = strings.TrimPrefix(uri, "sip:")
	if i := strings.IndexByte(uri, '@'); i > 0 {
		return uri[:i]
	}
	return ""
}

// handlePreEstablishedInvite implements clause 8.2.2.
func (s *Server) handlePreEstablishedInvite(ctx context.Context, send responder, msg *Message, source, transport string) {
	localTag := newToken()
	callID := msg.Header("Call-ID")
	owner := identityFrom(msg)

	// Step 2: the establishing user must be served; refusal carries the
	// clause 4.4 warning "100 function not allowed" shape.
	if !s.servedUserExists(ctx, owner) {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("100 function not allowed due to user not known to the participating function")}, nil)
		return
	}

	// Step 6: an audio media stream must be offered.
	offer, _ := s.sdpOffer(msg)
	info := parseSDP(offer)
	if info.Audio.Port == 0 {
		s.respond(send, msg, 488, "Not Acceptable Here", nil, nil)
		return
	}

	// Step 8: the URI identifying the pre-established session.
	pesURI := fmt.Sprintf("sip:mcptt-pes-%s@%s", newToken(), advertiseHostOnly(s.cfg))

	if _, err := s.st.CreateDialog(ctx, store.Dialog{
		CallID:       callID,
		LocalTag:     localTag,
		RemoteTag:    tagFrom(msg.Header("From")),
		FromURI:      identityFromHeader(msg.Header("From")),
		ToURI:        identityFromHeader(msg.Header("To")),
		RequestURI:   msg.URI,
		IMPU:         identityFromHeader(msg.Header("From")),
		MCPTTID:      owner,
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
		slog.Warn("pre-established dialog store failed", "err", err, "call_id", callID)
	}

	body, _ := s.sdpAnswer(msg)
	now := time.Now().UTC()
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:               callID,
		State:                "established",
		InitiatorURI:         owner,
		TargetURI:            pesURI,
		LocalTag:             localTag,
		RemoteTag:            tagFrom(msg.Header("From")),
		Transport:            transport,
		SourceAddr:           source,
		AudioIP:              info.Audio.ConnectionIP,
		AudioPort:            info.Audio.Port,
		AudioProto:           info.Audio.Proto,
		AudioPayloads:        info.Audio.Payloads,
		FloorControlIP:       info.FloorControl.ConnectionIP,
		FloorControlPort:     info.FloorControl.Port,
		FloorControlProto:    info.FloorControl.Proto,
		FloorControlPayloads: info.FloorControl.Payloads,
		SDPOffer:             offer,
		SDPAnswer:            string(body),
		AnsweredAt:           now,
		EstablishedAt:        now,
	}); err != nil {
		slog.Warn("pre-established call store failed", "err", err, "call_id", callID)
	}

	s.pesSessions.Store(callID, &pesSession{
		uri: pesURI, owner: owner, sdp: info, offer: offer, answer: string(body), localTag: localTag,
	})
	s.markSessionAnswered(ctx, callID)

	// Step 9: the 200 carries the session URI in Contact, the PSI asserted,
	// and norefersub supported (the REFERs to come are answered without
	// implicit subscriptions).
	headers := []header{
		{"Contact", fmt.Sprintf("<%s>;+g.3gpp.mcptt", pesURI)},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"Supported", "norefersub, timer"},
		{"Session-Expires", sessionExpiresHeader},
		{"Allow", allowValue},
		{"Content-Type", "application/sdp"},
	}
	headers = append(recordRouteHeaders(s.recordRouteURI(transport), msg.HeadersFor("Record-Route")), headers...)
	slog.Info("pre-established session created", "call_id", callID, "owner", owner, "pes_uri", pesURI)
	s.respondTagged(send, msg, 200, "OK", localTag, headers, body)
}

// referGroupURI extracts the target group from a REFER: the entry of the
// cid-referenced resource-lists body (clause 10.1.1.3.1.2 condition 1), or a
// direct URI in Refer-To for clients that skip the cid indirection.
func referGroupURI(msg *Message) string {
	if entries := resourceListEntries(msg); len(entries) > 0 {
		return strings.TrimSpace(entries[0])
	}
	referTo := strings.TrimSpace(msg.Header("Refer-To"))
	referTo = strings.Trim(referTo, "<>")
	if i := strings.IndexAny(referTo, "?;"); i > 0 {
		referTo = referTo[:i]
	}
	if strings.HasPrefix(strings.ToLower(referTo), "sip:") && !strings.HasPrefix(strings.ToLower(referTo), "cid:") {
		return referTo
	}
	return ""
}

// handleRefer implements clause 10.1.1.3.1.2: a REFER on a pre-established
// session originates a group call reusing the session's media.
func (s *Server) handleRefer(ctx context.Context, send responder, msg *Message, source, transport string) {
	callID := msg.Header("Call-ID")
	v, ok := s.pesSessions.Load(callID)
	if !ok {
		s.respond(send, msg, 481, "Call/Transaction Does Not Exist", nil, nil)
		return
	}
	pes := v.(*pesSession)

	// Step 3: the calling user must still be bound.
	if !s.servedUserExists(ctx, pes.owner) {
		s.respond(send, msg, 404, "Not Found",
			[]header{s.mcpttWarning("141 user unknown to the participating function")}, nil)
		return
	}

	groupURI := referGroupURI(msg)
	if groupURI == "" {
		s.respond(send, msg, 404, "Not Found",
			[]header{s.mcpttWarning("142 unable to determine the controlling function")}, nil)
		return
	}

	// Admission by the group's controlling function (local or remote seam).
	controlling := s.controllingFor(groupURI)
	call := originatingGroupCall{
		CallID: callID, InitiatorURI: pes.owner, GroupURI: groupURI, SDP: pes.sdp,
	}
	if verdict := controlling.AdmitOriginatingCall(ctx, call); !verdict.Admitted {
		var extra []header
		if verdict.Warning != "" {
			extra = append(extra, s.mcpttWarning(verdict.Warning))
		}
		s.respond(send, msg, verdict.Status, verdict.Reason, extra, nil)
		return
	}

	// Steps 13-14: the final 200 with Refer-Sub: false - no implicit
	// subscription is created (RFC 4488).
	s.respond(send, msg, 200, "OK", []header{{"Refer-Sub", "false"}}, nil)

	// The session becomes the group call's originating leg: the stored media
	// endpoints join the group's relay set and the members are invited with
	// the pre-established SDP (clause 10.1.1.3.1.2 steps 15+ realised
	// in-process).
	sessionURI := s.allocateSessionIdentity(callID)
	_ = sessionURI
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:       callID,
		State:        "answered",
		InitiatorURI: pes.owner,
		TargetURI:    groupURI,
		GroupURI:     groupURI,
		MCPTTID:      groupURI,
		SDPOffer:     pes.offer,
		SDPAnswer:    pes.answer,
	}); err != nil {
		slog.Warn("pre-established group call store failed", "err", err, "call_id", callID)
	}
	controlling.EstablishGroupLegs(call)
	s.NotifyConferenceChange(groupURI)
	slog.Info("group call originated over pre-established session",
		"call_id", callID, "owner", pes.owner, "group_uri", groupURI)
}

// releasePreEstablished drops the session bookkeeping when its dialog ends.
func (s *Server) releasePreEstablished(callID string) {
	if _, ok := s.pesSessions.LoadAndDelete(callID); ok {
		slog.Info("pre-established session released", "call_id", callID)
	}
}

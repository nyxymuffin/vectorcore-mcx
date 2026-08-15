package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Ad hoc group calls, TS 24.379 clause 17: a group session whose membership
// arrives with the INVITE (an application/resource-lists+xml body of MCPTT
// IDs) instead of from provisioned group documents. The controlling side here
// implements clause 17.4.2.2 for the on-demand, participant-list case.
//
// The <call-participants-criterias> path (step 12's criteria evaluation) is
// deliberately not implemented in the base: participant determination from
// criteria is railway semantics behind the FRMCS profile per the project
// plan. A request carrying criteria without a list is refused with warning
// "187", which is also what a criteria-incapable controlling function must
// answer.

// sessionTypeFromBody extracts <session-type> from the mcptt-info body.
func sessionTypeFromBody(msg *Message) string {
	body := msg.Body
	if part := msg.Part("application/vnd.3gpp.mcptt-info+xml"); part != nil {
		body = part.Body
	}
	return strings.ToLower(xmlElementText(string(body), "session-type"))
}

// resourceListEntries returns the uri attributes of every <entry> element in
// the application/resource-lists+xml body (RFC 5366).
func resourceListEntries(msg *Message) []string {
	part := msg.Part("application/resource-lists+xml")
	if part == nil {
		return nil
	}
	text := string(part.Body)
	var entries []string
	for {
		i := strings.Index(text, "<entry")
		if i < 0 {
			break
		}
		text = text[i:]
		end := strings.Index(text, ">")
		if end < 0 {
			break
		}
		if v := xmlAttr(text[:end], "uri"); v != "" {
			entries = append(entries, v)
		}
		text = text[end:]
	}
	return entries
}

// callParticipantsCriteria extracts <call-participants-criterias> from the
// mcptt-info body; the base server only detects it, it does not evaluate it.
func callParticipantsCriteria(msg *Message) string {
	body := msg.Body
	if part := msg.Part("application/vnd.3gpp.mcptt-info+xml"); part != nil {
		body = part.Body
	}
	return xmlElementText(string(body), "call-participants-criterias")
}

// handleAdhocInvite implements the controlling side of clause 17.4.2.2 for an
// on-demand ad hoc group call with an explicit participant list.
func (s *Server) handleAdhocInvite(ctx context.Context, send responder, msg *Message, source, transport string) {
	localTag := newToken()
	callID := msg.Header("Call-ID")
	initiatorURI := identityFrom(msg)

	// The originating participating check of clause 10.1.1.3.1.1 steps 2/2a
	// applies to ad hoc originations too: the caller must be a served user.
	if !s.servedUserExists(ctx, initiatorURI) {
		slog.Warn("MCPTT adhoc INVITE from unknown user rejected",
			"call_id", callID, "initiator", initiatorURI,
			"warning", "141 user unknown to the participating function")
		s.respond(send, msg, 404, "Not Found",
			[]header{s.mcpttWarning("141 user unknown to the participating function")}, nil)
		return
	}

	// Step 5: the service must support ad hoc group calls; refusal carries
	// warning "186". The service-configuration element is stood in for by
	// sip.adhoc.enabled until the CMS generates it.
	if !s.cfg.SIP.Adhoc.Enabled {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("186 the MCPTT system do not support adhoc group call")}, nil)
		return
	}

	entries := resourceListEntries(msg)
	criteria := callParticipantsCriteria(msg)

	// Step 7: a list and criteria together are contradictory.
	if len(entries) > 0 && criteria != "" {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("187 can't determine the adhoc group participants")}, nil)
		return
	}
	// Criteria without a list: participant determination from criteria is not
	// available in the base server (FRMCS profile scope), and no list means
	// the participants cannot be determined.
	if len(entries) == 0 {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("187 can't determine the adhoc group participants")}, nil)
		return
	}
	// Step 6: participant count within the configured limit, warning "189".
	if max := s.cfg.SIP.Adhoc.MaxParticipants; max > 0 && len(entries) > max {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("189 maximum number of allowed adhoc group participants exceeded")}, nil)
		return
	}

	// Step 10: the adhoc group identity comes from <mcptt-request-uri> when
	// the client supplied one, otherwise the controlling function generates
	// it. The generated identity deliberately carries no user or group
	// information (the clause 4.5 sensitivity rule applies to it too).
	adhocID := mcpttIdentityFromBody(msg)
	if adhocID == "" || !strings.HasPrefix(strings.ToLower(adhocID), "sip:") {
		adhocID = fmt.Sprintf("sip:mcptt-adhoc-%s@%s", newToken(), s.cfg.IMS.Realm)
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
		MCPTTID:      adhocID,
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
		slog.Warn("adhoc dialog store failed", "err", err, "call_id", callID)
	}

	slog.Info("MCPTT adhoc group INVITE",
		"call_id", callID, "initiator", initiatorURI, "adhoc_group", adhocID,
		"participants", len(entries), "source", source)

	s.uasInvites.Store(callID, &uasInviteState{msg: msg, send: send, tag: localTag})
	s.respond(send, msg, 100, "Trying", nil, nil)
	s.respondTagged(send, msg, 180, "Ringing", localTag,
		inviteResponseHeaders(s.advertisedSIPURI(transport), s.recordRouteURI(transport), msg.HeadersFor("Record-Route"), ""), nil)

	body, _ := s.sdpAnswer(msg)
	now := time.Now().UTC()
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:               callID,
		State:                "answered",
		InitiatorURI:         initiatorURI,
		TargetURI:            adhocID,
		GroupURI:             adhocID,
		MCPTTID:              adhocID,
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
		AnsweredAt:           now,
	}); err != nil {
		slog.Warn("adhoc call store failed", "err", err, "call_id", callID)
	}
	if sdpGrantsImplicitFloor(body) {
		if _, err := s.st.UpdateCallFloorState(ctx, callID, store.FloorStateUpdate{
			State: "granted", Event: "sdp_granted", Subtype: 1, At: now,
		}); err != nil {
			slog.Warn("adhoc floor grant store failed", "err", err, "call_id", callID)
		}
	}

	// Step 13: session identity at session creation; step 15: invite the
	// determined members before the originator's final response (the same
	// ordering rule as the prearranged flow, clause 10.1.1.4.2 step 14 g v);
	// step 16: the invited members count as implicitly affiliated, which the
	// media relay realises by keying on the call records this creates.
	sessionURI := s.allocateSessionIdentity(callID)
	s.establishAdhocLegs(ctx, callID, adhocID, initiatorURI, entries, sdpInfo)

	// The 200 per clause 6.3.3.2.3.2, with the mcptt-info body telling the
	// originator the (possibly generated) adhoc group identity.
	infoBody := fmt.Sprintf(
		`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
			`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
			`<session-type>adhoc</session-type>`+
			`</mcptt-Params></mcpttinfo>`, adhocID)
	const boundary = "mcxasadhoc"
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

// establishAdhocLegs invites each listed participant, reusing the RX leg
// machinery of the prearranged flow. Legs are initiated synchronously so the
// originator's 200 follows them onto the wire.
func (s *Server) establishAdhocLegs(ctx context.Context, txCallID, adhocID, initiatorURI string, entries []string, txSDP sdpInfo) {
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		slog.Warn("adhoc legs: list users failed", "err", err)
		return
	}
	regs, err := s.st.ListRegistrations(ctx)
	if err != nil {
		slog.Warn("adhoc legs: list registrations failed", "err", err)
		return
	}
	regByImpu := make(map[string]store.Registration, len(regs))
	for _, r := range regs {
		if r.Registered {
			regByImpu[strings.TrimSpace(r.PublicIdentity)] = r
		}
	}

	audioPayload := "114 96 9 0 8"
	if len(txSDP.Audio.Payloads) > 0 {
		audioPayload = strings.Join(txSDP.Audio.Payloads, " ")
	}

	for _, member := range entries {
		member = strings.TrimSpace(member)
		// A listed participant is an MCPTT ID; resolve it to a served user's
		// IMPU the same way group-member legs do.
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
			slog.Info("adhoc leg skipped: participant not a served user", "member", member)
			continue
		}
		if strings.EqualFold(impu, strings.TrimSpace(initiatorURI)) {
			continue
		}
		reg, ok := regByImpu[impu]
		if !ok || !reg.Registered {
			slog.Info("adhoc leg skipped: participant not registered", "member", member)
			continue
		}
		// Clause 10.1.1.3.2 step 3 applies to each invited participant: no
		// published Answer-Mode Indication means the leg is not established
		// (warning "146" semantics, in-process).
		mode := s.answerModeFor(ctx, impu)
		if mode == answerModeUnknown {
			slog.Warn("adhoc leg skipped: no usable poc-settings",
				"member", impu, "warning", "146 T-PF unable to determine the service settings for the called user")
			continue
		}
		s.sendRXInvite(context.Background(), txCallID, adhocID, initiatorURI, impu, audioPayload, "adhoc", reg, mode, nil)
	}
}

package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Remote controlling binding: slice 5 of the Phase 2a design. A group listed
// in sip.remote_groups homes its controlling function (TS 24.379 clause
// 6.3.3) at another MC system, an IWF, or a gateway server, and this server
// acts purely as the originating participating function for it: the whole
// originating exchange is relayed over SIP per clauses 10.1.1.3.1.1,
// 6.3.2.1.3 (the forwarded INVITE) and 6.3.2.1.5.2 (the relayed final
// response).

// remoteControlling is the seam's SIP-speaking implementation.
type remoteControlling struct {
	s   *Server
	cfg config.RemoteGroupConfig
}

// The controllingFunction methods exist so the binding satisfies the seam,
// but a remote group's admission and legs live at the remote system: the
// verdict is whatever the forwarded INVITE's final response says, so these
// are not meaningful locally. handleInvite recognises the binding and takes
// the relay path instead of calling them.
func (r remoteControlling) AdmitOriginatingCall(context.Context, originatingGroupCall) admissionVerdict {
	return admissionVerdict{Admitted: true}
}
func (r remoteControlling) EstablishGroupLegs(originatingGroupCall) {}
func (r remoteControlling) ReleaseGroupLegs(groupURI, callID string) {
	r.s.relayRemoteBye(groupURI, callID)
}

// remoteInviteState is what an in-flight relayed INVITE needs for a CANCEL
// toward the remote controlling function (RFC 3261 clause 9.1: the CANCEL
// mirrors the INVITE's Via branch, From, To, Call-ID and CSeq number).
type remoteInviteState struct {
	branch      string
	target      string
	transport   string
	fromHeader  string
	toHeader    string
	relayCallID string
	cancelled   atomic.Bool
}

// remoteSessionState is what a relayed session needs for later in-dialog
// requests toward the remote controlling function.
type remoteSessionState struct {
	cfg           config.RemoteGroupConfig
	remoteContact string
	remoteTag     string
	localFromTag  string
	callID        string
	routeSet      []string
}

// relayToRemoteControlling forwards an originating group INVITE to the
// remote controlling function and relays its verdict to the originator.
func (s *Server) relayToRemoteControlling(ctx context.Context, send responder, msg *Message, rc remoteControlling, call originatingGroupCall, localTag, transport string) {
	target := strings.TrimSpace(rc.cfg.Target)
	if target == "" && strings.TrimSpace(rc.cfg.ControllingPSI) != "" {
		// addrFromSIPURI returns ":5060" for a host-less URI, which would
		// dial nothing useful; require a real host.
		if addr := addrFromSIPURI(rc.cfg.ControllingPSI); addr != "" && !strings.HasPrefix(addr, ":") {
			target = addr
		}
	}
	if target == "" {
		// TS 24.379 clause 10.1.1.3.1.1: unable to identify the controlling
		// function for the group.
		s.respond(send, msg, 404, "Not Found",
			[]header{s.mcpttWarning("142 unable to determine the controlling function")}, nil)
		return
	}
	remoteTransport := strings.ToLower(strings.TrimSpace(rc.cfg.Transport))
	if remoteTransport == "" {
		remoteTransport = "udp"
	}

	// Body: the client's SDP offer passed through (clause 6.3.2.1.1.1) plus
	// the mcptt-info body with <mcptt-calling-user-id> set to the calling
	// user's MCPTT ID (clause 10.1.1.3.1.1 step 5). The info body is rebuilt
	// rather than copied because the inbound leg may not have carried one.
	clientOffer, _ := s.sdpOffer(msg)
	// Clause 6.3.2.1.2.1 steps 1-2: the participating function anchors the
	// media, so the offer toward the remote advertises this server's media
	// and floor control endpoints rather than the client's.
	anchorHost := s.mediaAnchorHost()
	anchorAudio, anchorFloor := s.mediaAnchorPorts()
	offer := anchorSDP(clientOffer, anchorHost, anchorAudio, anchorFloor)
	mcpttInfo := fmt.Sprintf(
		`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
			`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
			`<mcptt-calling-user-id><mcpttURI>%s</mcpttURI></mcptt-calling-user-id>`+
			`<session-type>prearranged</session-type>`+
			`</mcptt-Params></mcpttinfo>`,
		call.GroupURI, call.InitiatorURI,
	)
	const boundary = "mcxasrelay"
	body := fmt.Sprintf(
		"--%s\r\nContent-Type: application/sdp\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n%s\r\n--%s--\r\n",
		boundary, offer, boundary, mcpttInfo, boundary,
	)

	// Headers per clause 6.3.2.1.3: Accept-/Reject-Contact copied, session
	// timer offered without a refresher, timer supported, P-Asserted-Identity
	// set to this participating function's PSI, the mcptt feature tag in the
	// Contact, and the ICSI in P-Asserted-Service. Answer-Mode and
	// Priv-Answer-Mode are deliberately not copied (clause 10.1.1.3.1.1
	// step 4).
	branch := rfc3261BranchCookie + newToken()
	fromTag := newToken()
	relayCallID := newToken()
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(remoteTransport), advertiseHost(s.cfg), branch)},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, fromTag)},
		{"To", fmt.Sprintf("<%s>", rc.cfg.ControllingPSI)},
		{"Call-ID", relayCallID},
		{"CSeq", "1 INVITE"},
		{"Contact", fmt.Sprintf("<%s>;+g.3gpp.mcptt", s.advertisedSIPURI(remoteTransport))},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"P-Asserted-Service", "urn:urn-7:3gpp-service.ims.icsi.mcptt"},
		{"Session-Expires", "1800"},
		{"Supported", "timer"},
		{"Content-Type", fmt.Sprintf(`multipart/mixed;boundary="%s"`, boundary)},
	}
	for _, ac := range msg.HeadersFor("Accept-Contact") {
		hdrs = append(hdrs, header{"Accept-Contact", ac})
	}
	for _, rj := range msg.HeadersFor("Reject-Contact") {
		hdrs = append(hdrs, header{"Reject-Contact", rj})
	}
	invite := buildRequest("INVITE", rc.cfg.ControllingPSI, hdrs, []byte(body))

	slog.Info("relaying group INVITE to remote controlling function",
		"call_id", call.CallID, "relay_call_id", relayCallID, "group_uri", call.GroupURI,
		"psi", rc.cfg.ControllingPSI, "target", target, "transport", remoteTransport)

	// Registered before the send so a CANCEL arriving while the relayed
	// INVITE rings can be relayed too (clause 6.3.2.1.4 territory).
	s.remoteInvites.Store(call.CallID, &remoteInviteState{
		branch: branch, target: target, transport: remoteTransport,
		fromHeader:  fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, fromTag),
		toHeader:    fmt.Sprintf("<%s>", rc.cfg.ControllingPSI),
		relayCallID: relayCallID,
	})
	final := s.sendTransacted(ctx, remoteTransport, target, branch, "INVITE", []byte(invite))
	resp := <-final
	cancelled := false
	if v, ok := s.remoteInvites.LoadAndDelete(call.CallID); ok {
		cancelled = v.(*remoteInviteState).cancelled.Load()
	}

	if resp == nil {
		// Timer B expired or the send failed; nothing came back to relay.
		s.respond(send, msg, 504, "Server Time-out", nil, nil)
		return
	}

	status := responseStatusCode(resp)
	if status < 200 {
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}

	if status >= 300 {
		// Relay the remote verdict, carrying its Warning texts through
		// (the transaction layer has already ACKed the non-2xx final).
		reason := "Forbidden"
		if f := strings.SplitN(resp.StartLine, " ", 3); len(f) == 3 {
			reason = f[2]
		}
		var extra []header
		for _, w := range resp.HeadersFor("Warning") {
			extra = append(extra, header{"Warning", w})
		}
		s.respond(send, msg, status, reason, extra, nil)
		return
	}

	// 2xx: ACK the remote 200 (UAC core, RFC 3261 clause 13), remember the
	// dialog for BYE relay, and answer the originator per clause 6.3.2.1.5.2
	// with the remote SDP answer and a locally mapped session identity.
	remoteContact := uriFromHeader(resp.Header("Contact"))
	remoteTag := tagFrom(resp.Header("To"))
	recordRoutes := resp.HeadersFor("Record-Route")
	routeSet := make([]string, len(recordRoutes))
	for i, rr := range recordRoutes {
		routeSet[len(recordRoutes)-1-i] = rr
	}
	s.ackRemote200(ctx, rc.cfg, remoteTransport, target, relayCallID, fromTag, resp)

	s.remoteSessions.Store(call.CallID, remoteSessionState{
		cfg: rc.cfg, remoteContact: remoteContact, remoteTag: remoteTag,
		localFromTag: fromTag, callID: relayCallID, routeSet: routeSet,
	})

	if cancelled {
		// RFC 3261 clause 9.1: the callee answered before the CANCEL took
		// effect. The caller already got its 487, so the freshly created
		// remote dialog is released immediately.
		slog.Info("remote 200 raced the CANCEL; releasing the remote session",
			"call_id", call.CallID, "relay_call_id", relayCallID)
		s.relayRemoteBye(call.GroupURI, call.CallID)
		return
	}

	remoteAnswer := ""
	ct := strings.ToLower(resp.Header("Content-Type"))
	if strings.Contains(ct, "application/sdp") {
		remoteAnswer = string(resp.Body)
	} else if part := resp.Part("application/sdp"); part != nil {
		remoteAnswer = string(part.Body)
	}
	// The client is answered with this server's media endpoints, so its RTP
	// and floor control arrive here and are relayed onward.
	answer := anchorSDP(remoteAnswer, anchorHost, anchorAudio, anchorFloor)

	sessionURI := s.allocateSessionIdentity(call.CallID)

	// Two call records sharing the session identity as their group: the
	// client leg and the remote leg. The media observer relays RTP between
	// legs of the same group, which is what anchoring requires.
	clientSDP := parseSDP(clientOffer)
	remoteSDP := parseSDP(remoteAnswer)
	now := time.Now().UTC()
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:               call.CallID,
		State:                "answered",
		InitiatorURI:         call.InitiatorURI,
		TargetURI:            call.GroupURI,
		GroupURI:             sessionURI,
		MCPTTID:              call.GroupURI,
		LocalTag:             localTag,
		RemoteTag:            tagFrom(msg.Header("From")),
		Transport:            transport,
		AudioIP:              clientSDP.Audio.ConnectionIP,
		AudioPort:            clientSDP.Audio.Port,
		AudioProto:           clientSDP.Audio.Proto,
		AudioPayloads:        clientSDP.Audio.Payloads,
		FloorControlIP:       clientSDP.FloorControl.ConnectionIP,
		FloorControlPort:     clientSDP.FloorControl.Port,
		FloorControlProto:    clientSDP.FloorControl.Proto,
		FloorControlPayloads: clientSDP.FloorControl.Payloads,
		LocalAudioPort:       anchorAudio,
		LocalFloorPort:       anchorFloor,
		SDPOffer:             clientOffer,
		SDPAnswer:            answer,
		AnsweredAt:           now,
		EstablishedAt:        now,
	}); err != nil {
		slog.Warn("relayed client leg store failed", "call_id", call.CallID, "err", err)
	}
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:               relayCallID,
		State:                "established",
		InitiatorURI:         s.cfg.MCX.SIPIdentity,
		TargetURI:            rc.cfg.ControllingPSI,
		GroupURI:             sessionURI,
		MCPTTID:              call.GroupURI,
		RemoteTarget:         remoteContact,
		Transport:            remoteTransport,
		SourceAddr:           target,
		AudioIP:              remoteSDP.Audio.ConnectionIP,
		AudioPort:            remoteSDP.Audio.Port,
		AudioProto:           remoteSDP.Audio.Proto,
		AudioPayloads:        remoteSDP.Audio.Payloads,
		FloorControlIP:       remoteSDP.FloorControl.ConnectionIP,
		FloorControlPort:     remoteSDP.FloorControl.Port,
		FloorControlProto:    remoteSDP.FloorControl.Proto,
		FloorControlPayloads: remoteSDP.FloorControl.Payloads,
		LocalAudioPort:       anchorAudio,
		LocalFloorPort:       anchorFloor,
		SDPOffer:             offer,
		SDPAnswer:            remoteAnswer,
		AnsweredAt:           now,
		EstablishedAt:        now,
	}); err != nil {
		slog.Warn("relayed remote leg store failed", "call_id", relayCallID, "err", err)
	}
	headers := []header{
		{"Contact", fmt.Sprintf("<%s>;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mcptt\";isfocus", sessionURI)},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"Session-Expires", "1800;refresher=uac"},
		{"Require", "timer"},
		{"Supported", "tdialog, norefersub"},
		{"Allow", allowValue},
	}
	headers = append(recordRouteHeaders(s.recordRouteURI(transport), msg.HeadersFor("Record-Route")), headers...)
	if answer != "" {
		headers = append(headers, header{"Content-Type", "application/sdp"})
	}
	s.uasInvites.Delete(call.CallID)
	s.respondTagged(send, msg, 200, "OK", localTag, headers, []byte(answer))
	slog.Info("remote group session established",
		"call_id", call.CallID, "relay_call_id", relayCallID, "group_uri", call.GroupURI)
}

// ackRemote200 sends the UAC-core ACK for the remote 200 (RFC 3261 clause 13:
// Request-URI from the remote Contact, Route from the reversed Record-Route).
func (s *Server) ackRemote200(ctx context.Context, cfg config.RemoteGroupConfig, transport, target, callID, fromTag string, resp *Message) {
	remoteContact := uriFromHeader(resp.Header("Contact"))
	reqURI := remoteContact
	if reqURI == "" {
		reqURI = cfg.ControllingPSI
	}
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(transport), advertiseHost(s.cfg), rfc3261BranchCookie+newToken())},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, fromTag)},
		{"To", resp.Header("To")},
		{"Call-ID", callID},
		{"CSeq", "1 ACK"},
	}
	recordRoutes := resp.HeadersFor("Record-Route")
	for i := len(recordRoutes) - 1; i >= 0; i-- {
		hdrs = append(hdrs, header{"Route", recordRoutes[i]})
	}
	ack := buildRequest("ACK", reqURI, hdrs, nil)
	if err := s.sendOutbound(ctx, transport, target, []byte(ack)); err != nil {
		slog.Warn("remote 200 ACK send failed", "call_id", callID, "err", err)
	}
}

// relayRemoteBye ends the remote session when the originator's leg ends
// (TS 24.379 clause 6.3.2.1.6: Request-URI set to the session identity /
// remote target, P-Asserted-Identity the participating function's PSI).
func (s *Server) relayRemoteBye(groupURI, callID string) {
	v, ok := s.remoteSessions.LoadAndDelete(callID)
	if !ok {
		return
	}
	state := v.(remoteSessionState)
	transport := strings.ToLower(strings.TrimSpace(state.cfg.Transport))
	if transport == "" {
		transport = "udp"
	}
	target := strings.TrimSpace(state.cfg.Target)
	if target == "" {
		target = addrFromSIPURI(state.cfg.ControllingPSI)
	}
	reqURI := state.remoteContact
	if reqURI == "" {
		reqURI = state.cfg.ControllingPSI
	}

	branch := rfc3261BranchCookie + newToken()
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(transport), advertiseHost(s.cfg), branch)},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, state.localFromTag)},
		{"To", fmt.Sprintf("<%s>;tag=%s", state.cfg.ControllingPSI, state.remoteTag)},
		{"Call-ID", state.callID},
		{"CSeq", "2 BYE"},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
	}
	for _, r := range state.routeSet {
		if strings.TrimSpace(r) != "" {
			hdrs = append(hdrs, header{"Route", r})
		}
	}
	bye := buildRequest("BYE", reqURI, hdrs, nil)
	slog.Info("relaying BYE to remote controlling function",
		"call_id", callID, "relay_call_id", state.callID, "group_uri", groupURI)
	s.sendTransacted(context.Background(), transport, target, branch, "BYE", []byte(bye))
}

// remoteGroupFor returns the remote homing configuration for a group, if any.
func (s *Server) remoteGroupFor(groupURI string) (config.RemoteGroupConfig, bool) {
	for _, rg := range s.cfg.SIP.RemoteGroups {
		if strings.EqualFold(strings.TrimSpace(rg.GroupURI), strings.TrimSpace(groupURI)) {
			return rg, true
		}
	}
	return config.RemoteGroupConfig{}, false
}

// relayRemoteCancel forwards a caller's CANCEL toward the remote controlling
// function while the relayed INVITE is still in flight (RFC 3261 clause 9.1:
// same branch, Via, From, To, Call-ID; CSeq method CANCEL). Reports whether
// there was an in-flight relay to cancel.
func (s *Server) relayRemoteCancel(callID string) bool {
	v, ok := s.remoteInvites.Load(callID)
	if !ok {
		return false
	}
	state := v.(*remoteInviteState)
	state.cancelled.Store(true)
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(state.transport), advertiseHost(s.cfg), state.branch)},
		{"Max-Forwards", "70"},
		{"From", state.fromHeader},
		{"To", state.toHeader},
		{"Call-ID", state.relayCallID},
		{"CSeq", "1 CANCEL"},
	}
	// The CANCEL target PSI comes from the To header's URI.
	reqURI := strings.Trim(strings.TrimSpace(strings.Split(state.toHeader, ">")[0]), "<")
	cancel := buildRequest("CANCEL", reqURI, hdrs, nil)
	slog.Info("relaying CANCEL to remote controlling function",
		"call_id", callID, "relay_call_id", state.relayCallID, "target", state.target)
	if err := s.sendOutbound(context.Background(), state.transport, state.target, []byte(cancel)); err != nil {
		slog.Warn("remote CANCEL send failed", "call_id", callID, "err", err)
	}
	return true
}

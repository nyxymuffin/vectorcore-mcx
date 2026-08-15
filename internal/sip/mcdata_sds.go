package sip

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// MCData standalone SDS over the signalling control plane, TS 24.282 clause
// 9.2.2: a SIP MESSAGE carrying mcdata-info, mcdata-signalling and
// mcdata-payload MIME bodies, distributed by the controlling MCData function
// to the targeted user (one-to-one-sds), the affiliated group members
// (group-sds) or a listed participant set (ad-hoc-group-sds), answered with
// 202 (Accepted) toward the originator (clause 9.2.2.4.2 steps 7-8).

const (
	ctMcdataInfo       = "application/vnd.3gpp.mcdata-info+xml"
	ctMcdataSignalling = "application/vnd.3gpp.mcdata-signalling"
	ctMcdataPayload    = "application/vnd.3gpp.mcdata-payload"
)

// mcdataURIFrom extracts a URI element that may wrap its value in
// <mcdataURI> per the mcdata-info schema.
func mcdataURIFrom(info, name string) string {
	inner := xmlElementText(info, name)
	if uri := strings.TrimSpace(xmlElementText(inner, "mcdataURI")); uri != "" {
		return uri
	}
	return strings.TrimSpace(inner)
}

func mcdataInfoBody(msg *Message) string {
	if part := msg.Part(ctMcdataInfo); part != nil {
		return string(part.Body)
	}
	if strings.Contains(strings.ToLower(msg.Header("Content-Type")), ctMcdataInfo) {
		return string(msg.Body)
	}
	return ""
}

// handleMessage dispatches SIP MESSAGE requests: MCData SDS goes through the
// controlling function; anything else is acknowledged (MESSAGE is advertised
// in Allow, so a 405 was wrong for it).
func (s *Server) handleMessage(ctx context.Context, send responder, msg *Message, source, transport string) {
	if mcdataInfoBody(msg) != "" {
		s.handleMcdataSDS(ctx, send, msg, source, transport)
		return
	}
	// An mcptt-info body carrying <alert-ind> is an emergency alert MESSAGE
	// (TS 24.379 clause 12.1.3).
	if info := mcpttInfoOf(msg); info != "" && strings.Contains(info, "<alert-ind>") {
		s.handleMcpttAlertMessage(ctx, send, msg, source)
		return
	}
	// A location-info body is a location report or request (clause 13.2).
	if locationInfoOf(msg) != "" {
		s.handleLocationMessage(ctx, send, msg, source)
		return
	}
	slog.Info("SIP MESSAGE received (non-MCData)", "call_id", msg.Header("Call-ID"), "source", source)
	s.respond(send, msg, 200, "OK", nil, nil)
}

func (s *Server) handleMcdataSDS(ctx context.Context, send responder, msg *Message, source, transport string) {
	callID := msg.Header("Call-ID")
	initiatorURI := identityFrom(msg)
	info := mcdataInfoBody(msg)
	requestType := strings.ToLower(strings.TrimSpace(xmlElementText(info, "request-type")))

	// A signalling body without a payload is a disposition notification
	// (TS 24.282 clause 12.2.3), not a standalone SDS.
	if msg.Part(ctMcdataSignalling) != nil && msg.Part(ctMcdataPayload) == nil {
		s.handleMcdataDisposition(ctx, send, msg, source)
		return
	}
	// Clause 9.2.2.4.2 step 2: all three MIME bodies must be present.
	if msg.Part(ctMcdataInfo) == nil || msg.Part(ctMcdataSignalling) == nil || msg.Part(ctMcdataPayload) == nil {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("199 expected MIME bodies not in the request")}, nil)
		return
	}

	// TS 24.282 clause 11.1 transmission limits on the payload size.
	payloadSize := len(msg.Part(ctMcdataPayload).Body)
	if max := s.cfg.SIP.MCData.MaxSingleRequestBytes; max > 0 && payloadSize > max {
		warning := "208 user not authorised for MCData communications on this group identity due to exceeding the maximum amount of data that can be sent in a single request"
		s.respond(send, msg, 403, "Forbidden", []header{s.mcpttWarning(warning)}, nil)
		return
	}
	if max := s.cfg.SIP.MCData.MaxSDSSizeBytes; max > 0 && payloadSize > max {
		warning := "218 user not authorised for one-to-one SDS communications due to message size"
		if requestType != "one-to-one-sds" {
			warning = "217 user not authorised for SDS communications on this group identity due to message size"
		}
		s.respond(send, msg, 403, "Forbidden", []header{s.mcpttWarning(warning)}, nil)
		return
	}

	slog.Info("MCData SDS MESSAGE", "call_id", callID, "initiator", initiatorURI,
		"request_type", requestType, "source", source)

	switch requestType {
	case "one-to-one-sds":
		// Step 5 b: exactly one target in the resource-lists body.
		entries := resourceListEntries(msg)
		if len(entries) != 1 {
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("204 unable to determine targeted user for one-to-one SDS")}, nil)
			return
		}
		if !s.forwardSDS(ctx, msg, strings.TrimSpace(entries[0]), "") {
			s.respond(send, msg, 404, "Not Found", nil, nil)
			return
		}
	case "group-sds":
		groupURI := mcdataURIFrom(info, "mcdata-request-uri")
		group := s.groupByURI(ctx, groupURI)
		if group == nil {
			s.respond(send, msg, 404, "Not Found",
				[]header{s.mcpttWarning("163 the group identity indicated in the request does not exist")}, nil)
			return
		}
		userID, groupID, ok := s.userGroupIDs(ctx, initiatorURI, groupURI)
		member := false
		if ok {
			member, _ = s.st.IsGroupMember(ctx, userID, groupID)
		}
		if !member {
			// Step 6 e: the originator must be listed in the group document.
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("116 user is not part of the MCData group")}, nil)
			return
		}
		if affiliated, _ := s.st.IsGroupAffiliated(ctx, userID, groupID); !affiliated {
			// Step 6 j: the originator must be affiliated.
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("120 user is not affiliated to this group")}, nil)
			return
		}
		// Step 6 k: the targeted members are the group's affiliated members.
		targets := s.affiliatedGroupMembers(ctx, groupID, initiatorURI)
		if len(targets) == 0 {
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("198 no users are affiliated to this group")}, nil)
			return
		}
		for _, target := range targets {
			s.forwardSDS(ctx, msg, target, groupURI)
		}
	case "ad-hoc-group-sds":
		// Step 6A: participants from the resource-lists body; criteria-based
		// determination is not implemented (240), and the participant count
		// respects the ad hoc limit (189).
		entries := resourceListEntries(msg)
		if len(entries) == 0 {
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("240 can't determine the adhoc group participants")}, nil)
			return
		}
		if max := s.cfg.SIP.Adhoc.MaxParticipants; max > 0 && len(entries) > max {
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("189 maximum number of allowed adhoc group participants exceeded")}, nil)
			return
		}
		adhocID := mcdataURIFrom(info, "mcdata-request-uri")
		if !strings.HasPrefix(strings.ToLower(adhocID), "sip:") {
			adhocID = fmt.Sprintf("sip:mcdata-adhoc-%s@%s", newToken(), s.cfg.IMS.Realm)
		}
		seen := map[string]bool{}
		for _, target := range entries {
			key := strings.ToLower(strings.TrimSpace(target))
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			s.forwardSDS(ctx, msg, strings.TrimSpace(target), adhocID)
		}
	default:
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("199 expected MIME bodies not in the request")}, nil)
		return
	}

	// Steps 7-8: 202 (Accepted) toward the originator.
	s.respond(send, msg, 202, "Accepted", nil, nil)
}

// affiliatedGroupMembers returns the IMPUs of the group's affiliated, enabled
// members other than the originator (TS 24.282 clause 6.3.4).
func (s *Server) affiliatedGroupMembers(ctx context.Context, groupID, initiatorURI string) []string {
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return nil
	}
	memberships, err := s.st.ListGroupMemberships(ctx)
	if err != nil {
		return nil
	}
	userByID := make(map[string]store.User, len(users))
	for _, u := range users {
		userByID[u.ID] = u
	}
	var out []string
	for _, m := range memberships {
		if m.GroupID != groupID {
			continue
		}
		user, ok := userByID[m.UserID]
		if !ok || !user.Enabled {
			continue
		}
		affiliated, err := s.st.IsGroupAffiliated(ctx, m.UserID, groupID)
		if err != nil || !affiliated {
			continue
		}
		impu := strings.TrimSpace(user.IMPU)
		if impu == "" {
			impu = strings.TrimSpace(user.MCPTTID)
		}
		if impu == "" || strings.EqualFold(impu, strings.TrimSpace(initiatorURI)) {
			continue
		}
		out = append(out, impu)
	}
	return out
}

// forwardSDS generates the outgoing SIP MESSAGE of clause 9.2.2.4.1.1 toward
// one target: the three MCData MIME bodies copied, <mcdata-request-uri>
// rewritten to the target, <mcdata-calling-group-id> set for group and ad hoc
// SDS, the MCData SDS feature tags in Accept-Contact, and the PSI asserted.
// Returns false when the target has no registered binding.
func (s *Server) forwardSDS(ctx context.Context, msg *Message, target, callingGroupID string) bool {
	regs, err := s.st.ListRegistrations(ctx)
	if err != nil {
		return false
	}
	var reg *store.Registration
	targetImpu := target
	if users, err := s.st.ListUsers(ctx); err == nil {
		for _, user := range users {
			if !user.Enabled {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(user.MCPTTID), target) ||
				strings.EqualFold(strings.TrimSpace(user.IMPU), target) {
				if impu := strings.TrimSpace(user.IMPU); impu != "" {
					targetImpu = impu
				}
				break
			}
		}
	}
	for _, r := range regs {
		if r.Registered && strings.EqualFold(strings.TrimSpace(r.PublicIdentity), targetImpu) {
			candidate := r
			reg = &candidate
			break
		}
	}
	if reg == nil {
		slog.Info("MCData SDS target not registered", "target", target)
		return false
	}

	info := mcdataInfoBody(msg)
	info = setXMLURIElement(info, "mcdata-request-uri", target)
	if callingGroupID != "" {
		info = setXMLURIElement(info, "mcdata-calling-group-id", callingGroupID)
	}
	signalling := msg.Part(ctMcdataSignalling)
	payload := msg.Part(ctMcdataPayload)

	const boundary = "mcxassds"
	body := fmt.Sprintf(
		"--%s\r\nContent-Type: %s\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Type: %s\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Type: %s\r\n\r\n%s\r\n--%s--\r\n",
		boundary, ctMcdataInfo, info,
		boundary, ctMcdataSignalling, string(signalling.Body),
		boundary, ctMcdataPayload, string(payload.Body),
		boundary)

	transport := strings.ToLower(strings.TrimSpace(reg.Transport))
	if transport == "" {
		transport = "udp"
	}
	targetAddr := ""
	if reg.SourceIP != "" {
		port := reg.SourcePort
		if port == 0 {
			port = 5060
		}
		targetAddr = net.JoinHostPort(reg.SourceIP, strconv.Itoa(port))
	}
	if targetAddr == "" {
		return false
	}

	branch := rfc3261BranchCookie + newToken()
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(transport), advertiseHost(s.cfg), branch)},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, newToken())},
		{"To", fmt.Sprintf("<%s>", targetImpu)},
		{"Call-ID", newToken()},
		{"CSeq", "1 MESSAGE"},
		{"Accept-Contact", "*;+g.3gpp.mcdata.sds;require;explicit"},
		{"Accept-Contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.sds";require;explicit`},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"P-Asserted-Service", "urn:urn-7:3gpp-service.ims.icsi.mcdata.sds"},
		{"Content-Type", fmt.Sprintf(`multipart/mixed;boundary="%s"`, boundary)},
	}
	out := buildRequest("MESSAGE", targetImpu, hdrs, []byte(body))
	slog.Info("MCData SDS forwarding", "target", targetImpu, "addr", targetAddr, "group", callingGroupID)
	s.sendTransacted(ctx, transport, targetAddr, branch, "MESSAGE", []byte(out))
	return true
}

// setXMLURIElement replaces (or inserts) <name><mcdataURI>value</mcdataURI>
// </name> inside the mcdata-Params element of an mcdata-info body.
func setXMLURIElement(body, name, value string) string {
	element := "<" + name + "><mcdataURI>" + value + "</mcdataURI></" + name + ">"
	open := "<" + name
	if i := strings.Index(body, open); i >= 0 {
		if j := strings.Index(body[i:], "</"+name+">"); j >= 0 {
			return body[:i] + element + body[i+j+len("</"+name+">"):]
		}
	}
	if i := strings.Index(body, "<mcdata-Params>"); i >= 0 {
		at := i + len("<mcdata-Params>")
		return body[:at] + element + body[at:]
	}
	return body
}

// handleMcdataDisposition implements TS 24.282 clause 12.2.3: an SDS
// disposition notification (mcdata-signalling without a payload) is
// forwarded to the single user listed in the resource-lists body, with the
// SDS feature tags asserted and <mcdata-request-uri> rewritten (steps 3,
// 7-14).
func (s *Server) handleMcdataDisposition(ctx context.Context, send responder, msg *Message, source string) {
	entries := resourceListEntries(msg)
	if len(entries) != 1 {
		// Step 3: exactly one target.
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("145 unable to determine called party")}, nil)
		return
	}
	target := strings.TrimSpace(entries[0])
	slog.Info("MCData disposition notification", "target", target,
		"from", identityFrom(msg), "source", source)

	info := mcdataInfoBody(msg)
	info = setXMLURIElement(info, "mcdata-request-uri", target)
	signalling := msg.Part(ctMcdataSignalling)

	regs, err := s.st.ListRegistrations(ctx)
	if err != nil {
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	targetImpu := s.resolveServedImpu(ctx, target)
	var reg *store.Registration
	for _, r := range regs {
		if r.Registered && strings.EqualFold(strings.TrimSpace(r.PublicIdentity), targetImpu) {
			candidate := r
			reg = &candidate
			break
		}
	}
	if targetImpu == "" || reg == nil {
		s.respond(send, msg, 404, "Not Found", nil, nil)
		return
	}

	const boundary = "mcxasdisp"
	body := fmt.Sprintf(
		"--%s\r\nContent-Type: %s\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Type: %s\r\n\r\n%s\r\n--%s--\r\n",
		boundary, ctMcdataInfo, info,
		boundary, ctMcdataSignalling, string(signalling.Body),
		boundary)

	transport := strings.ToLower(strings.TrimSpace(reg.Transport))
	if transport == "" {
		transport = "udp"
	}
	targetAddr := ""
	if reg.SourceIP != "" {
		port := reg.SourcePort
		if port == 0 {
			port = 5060
		}
		targetAddr = net.JoinHostPort(reg.SourceIP, strconv.Itoa(port))
	}
	if targetAddr == "" {
		s.respond(send, msg, 404, "Not Found", nil, nil)
		return
	}
	branch := rfc3261BranchCookie + newToken()
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(transport), advertiseHost(s.cfg), branch)},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, newToken())},
		{"To", fmt.Sprintf("<%s>", targetImpu)},
		{"Call-ID", newToken()},
		{"CSeq", "1 MESSAGE"},
		{"Accept-Contact", "*;+g.3gpp.mcdata.sds;require;explicit"},
		{"Accept-Contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.sds";require;explicit`},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"P-Asserted-Service", "urn:urn-7:3gpp-service.ims.icsi.mcdata.sds"},
		{"Content-Type", fmt.Sprintf(`multipart/mixed;boundary="%s"`, boundary)},
	}
	out := buildRequest("MESSAGE", targetImpu, hdrs, []byte(body))
	s.sendTransacted(ctx, transport, targetAddr, branch, "MESSAGE", []byte(out))
	s.respond(send, msg, 200, "OK", nil, nil)
}

// resolveServedImpu maps an MCData/MCPTT ID to the served user's IMPU.
func (s *Server) resolveServedImpu(ctx context.Context, id string) string {
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return ""
	}
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(user.MCPTTID), id) ||
			strings.EqualFold(strings.TrimSpace(user.IMPU), id) {
			if impu := strings.TrimSpace(user.IMPU); impu != "" {
				return impu
			}
			return strings.TrimSpace(user.MCPTTID)
		}
	}
	return ""
}

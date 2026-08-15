package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// MCPTT emergency and imminent peril group calls, TS 24.379 clauses
// 6.3.3.1.13.2 (authorisation), 6.3.3.1.14 (rejection shape) and 6.3.3.1.19
// (Resource-Priority values). The in-progress emergency state of a group
// (clause 4.6) lives in memory and clears when the group's last leg ends;
// TNG2 (in-progress emergency group call timer, clause 6.3.3.1.16) is not
// yet supervised.

// Resource-Priority header values per RFC 4412/RFC 8101, mirroring the
// <emergency-resource-priority>/<imminent-peril-resource-priority>/
// <normal-resource-priority> elements the generated service configuration
// document advertises (namespace mcptt, priorities 0/1/5).
const (
	resourcePriorityEmergency = "mcptt.0"
	resourcePriorityImminent  = "mcptt.1"
)

// mcpttInfoFlagTrue reports whether the named mcptt-info element is "true".
func mcpttInfoFlagTrue(msg *Message, element string) bool {
	body := msg.Body
	if part := msg.Part("application/vnd.3gpp.mcptt-info+xml"); part != nil {
		body = part.Body
	}
	return strings.EqualFold(strings.TrimSpace(xmlElementText(string(body), element)), "true")
}

// emergencyCallAuthorised applies clause 6.3.3.1.13.2 with the provisioning
// stand-ins: the user profile ruleset is the user's AllowEmergencyCall flag,
// the group document's <allow-MCPTT-emergency-call> is the group's.
func (s *Server) emergencyCallAuthorised(ctx context.Context, initiatorURI string, group *store.Group) bool {
	if group == nil || !group.AllowEmergencyCall {
		return false
	}
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return false
	}
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(user.IMPU), strings.TrimSpace(initiatorURI)) ||
			strings.EqualFold(strings.TrimSpace(user.MCPTTID), strings.TrimSpace(initiatorURI)) {
			return user.AllowEmergencyCall
		}
	}
	return false
}

// priorityRejectBody is the SIP 403 body of clause 6.3.3.1.14: mcptt-info
// with the emergency and alert indications negated.
func priorityRejectBody() (string, string) {
	return `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
			`<emergency-ind>false</emergency-ind><alert-ind>false</alert-ind>` +
			`</mcptt-Params></mcpttinfo>`,
		"application/vnd.3gpp.mcptt-info+xml"
}

// priorityState is one group's in-progress emergency or imminent peril
// state. The deadline realises TNG2 (in-progress emergency group call timer,
// TS 24.379 clause 6.3.3.1.16): when it passes, the state falls back to
// normal. A zero deadline never expires.
type priorityState struct {
	kind     string
	deadline time.Time
	// by is the MCPTT ID that put the group into the state - cancellation
	// authorisation (clause 6.3.3.1.13.4) is keyed on it.
	by string
}

// groupPriorityState returns the in-progress emergency/imminent-peril state
// of a group: "emergency", "imminent" or "". An expired TNG2 clears the
// state on read (step 1 of clause 6.3.3.1.16).
func (s *Server) groupPriorityState(groupURI string) string {
	key := strings.ToLower(strings.TrimSpace(groupURI))
	v, ok := s.inProgressPriority.Load(key)
	if !ok {
		return ""
	}
	st := v.(priorityState)
	if !st.deadline.IsZero() && time.Now().UTC().After(st.deadline) {
		s.inProgressPriority.Delete(key)
		slog.Info("MCPTT in-progress emergency state expired (TNG2)", "group_uri", groupURI, "kind", st.kind)
		return ""
	}
	return st.kind
}

func (s *Server) setGroupPriorityState(groupURI, state string) {
	s.setGroupPriorityStateBy(groupURI, state, "")
}

func (s *Server) setGroupPriorityStateBy(groupURI, state, by string) {
	key := strings.ToLower(strings.TrimSpace(groupURI))
	if state == "" {
		s.inProgressPriority.Delete(key)
		return
	}
	st := priorityState{kind: state, by: strings.TrimSpace(by)}
	if state == "emergency" {
		if limit := s.cfg.SIP.Emergency.GroupTimeLimitSeconds; limit > 0 {
			st.deadline = time.Now().UTC().Add(time.Duration(limit) * time.Second)
		}
	}
	s.inProgressPriority.Store(key, st)
}

// groupPriorityStateBy returns the state kind and the MCPTT ID that set it.
func (s *Server) groupPriorityStateBy(groupURI string) (string, string) {
	key := strings.ToLower(strings.TrimSpace(groupURI))
	v, ok := s.inProgressPriority.Load(key)
	if !ok {
		return "", ""
	}
	st := v.(priorityState)
	if !st.deadline.IsZero() && time.Now().UTC().After(st.deadline) {
		s.inProgressPriority.Delete(key)
		return "", ""
	}
	return st.kind, st.by
}

// resourcePriorityFor returns the Resource-Priority value the controlling
// function includes in requests for this group (clause 6.3.3.1.19), or ""
// when the group is in no priority state (the normal value is only needed
// when downgrading, which re-INVITE handling will bring).
func (s *Server) resourcePriorityFor(groupURI string) string {
	switch s.groupPriorityState(groupURI) {
	case "emergency":
		return resourcePriorityEmergency
	case "imminent":
		return resourcePriorityImminent
	default:
		return ""
	}
}

// notifyGroupPriorityChange sends the clause 6.3.3.1.11 MESSAGE to every
// affiliated registered member other than the originator, carrying the given
// priority indicator element and value.
func (s *Server) notifyGroupPriorityChange(ctx context.Context, group *store.Group, groupURI, originator, element string, value bool) {
	if group == nil {
		return
	}
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return
	}
	memberships, err := s.st.ListGroupMemberships(ctx)
	if err != nil {
		return
	}
	userByID := map[string]store.User{}
	for _, u := range users {
		userByID[u.ID] = u
	}
	for _, m := range memberships {
		if m.GroupID != group.ID {
			continue
		}
		user, ok := userByID[m.UserID]
		if !ok || !user.Enabled {
			continue
		}
		if affiliated, _ := s.st.IsGroupAffiliated(ctx, m.UserID, group.ID); !affiliated {
			continue
		}
		impu := strings.TrimSpace(user.IMPU)
		if impu == "" {
			impu = strings.TrimSpace(user.MCPTTID)
		}
		if impu == "" || strings.EqualFold(impu, strings.TrimSpace(originator)) {
			continue
		}
		body := fmt.Sprintf(
			`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
				`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
				`<mcptt-calling-user-id><mcpttURI>%s</mcpttURI></mcptt-calling-user-id>`+
				`<mcptt-calling-group-id><mcpttURI>%s</mcpttURI></mcptt-calling-group-id>`+
				`<%s>%t</%s>`+
				`</mcptt-Params></mcpttinfo>`,
			impu, originator, groupURI, element, value, element)
		s.sendMcpttMessage(ctx, impu, body)
	}
}

// handlePriorityReInvite applies TS 24.379 clause 10.1.2.4.1.2 (and its
// prearranged sibling) to an in-dialog re-INVITE carrying <emergency-ind> or
// <imminentperil-ind>. It answers the request entirely when it returns true.
func (s *Server) handlePriorityReInvite(ctx context.Context, send responder, msg *Message) bool {
	info := mcpttInfoOf(msg)
	if info == "" ||
		(!strings.Contains(info, "<emergency-ind>") && !strings.Contains(info, "<imminentperil-ind>")) {
		return false
	}
	callID := msg.Header("Call-ID")
	call, err := s.st.GetCall(ctx, callID)
	if err != nil || call == nil {
		return false
	}
	groupURI := strings.TrimSpace(call.GroupURI)
	group := s.groupByURI(ctx, groupURI)
	initiator := identityFrom(msg)

	emergencyPresent := strings.Contains(info, "<emergency-ind>")
	emergencyTrue := mcpttInfoFlagTrue(msg, "emergency-ind")
	imminentPresent := strings.Contains(info, "<imminentperil-ind>")
	imminentTrue := mcpttInfoFlagTrue(msg, "imminentperil-ind")

	authorised := s.emergencyCallAuthorised(ctx, initiator, group)

	switch {
	case emergencyPresent && emergencyTrue:
		// Steps 3-4: upgrade to an emergency call.
		if !authorised {
			body, contentType := priorityRejectBody()
			s.respond(send, msg, 403, "Forbidden",
				[]header{{"Content-Type", contentType}}, []byte(body))
			return true
		}
		s.setGroupPriorityStateBy(groupURI, "emergency", initiator)
		s.notifyGroupPriorityChange(ctx, group, groupURI, initiator, "emergency-ind", true)
		slog.Info("MCPTT call upgraded to emergency", "call_id", callID, "group_uri", groupURI, "by", initiator)

	case emergencyPresent && !emergencyTrue:
		// Steps 5-6: cancellation. Authorised when the requester put the
		// group into the state (clause 6.3.3.1.13.4 stand-in).
		kind, by := s.groupPriorityStateBy(groupURI)
		if kind != "emergency" {
			return false // nothing to cancel; treat as a plain re-INVITE
		}
		if by != "" && !strings.EqualFold(by, strings.TrimSpace(initiator)) {
			body := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
				`<emergency-ind>true</emergency-ind></mcptt-Params></mcpttinfo>`
			s.respond(send, msg, 403, "Forbidden",
				[]header{{"Content-Type", "application/vnd.3gpp.mcptt-info+xml"}}, []byte(body))
			return true
		}
		s.setGroupPriorityState(groupURI, "")
		s.notifyGroupPriorityChange(ctx, group, groupURI, initiator, "emergency-ind", false)
		slog.Info("MCPTT in-progress emergency cancelled", "call_id", callID, "group_uri", groupURI, "by", initiator)

	case imminentPresent && imminentTrue:
		if !authorised {
			body, contentType := priorityRejectBody()
			s.respond(send, msg, 403, "Forbidden",
				[]header{{"Content-Type", contentType}}, []byte(body))
			return true
		}
		if s.groupPriorityState(groupURI) != "emergency" {
			s.setGroupPriorityStateBy(groupURI, "imminent", initiator)
			s.notifyGroupPriorityChange(ctx, group, groupURI, initiator, "imminentperil-ind", true)
			slog.Info("MCPTT call upgraded to imminent peril", "call_id", callID, "group_uri", groupURI, "by", initiator)
		}

	case imminentPresent && !imminentTrue:
		kind, by := s.groupPriorityStateBy(groupURI)
		if kind != "imminent" {
			return false
		}
		if by != "" && !strings.EqualFold(by, strings.TrimSpace(initiator)) {
			s.respond(send, msg, 403, "Forbidden", nil, nil)
			return true
		}
		s.setGroupPriorityState(groupURI, "")
		s.notifyGroupPriorityChange(ctx, group, groupURI, initiator, "imminentperil-ind", false)
		slog.Info("MCPTT in-progress imminent peril cancelled", "call_id", callID, "group_uri", groupURI, "by", initiator)
	default:
		return false
	}

	// The re-INVITE itself is answered like a session refresh (SDP answer,
	// Session-Expires) with the state change applied and the current
	// Resource-Priority reflected.
	s.markSessionAnswered(ctx, callID)
	body, contentType := s.sdpAnswer(msg)
	headers := []header{
		{"Allow", allowValue},
		{"Session-Expires", sessionExpiresHeader},
		{"Require", "timer"},
	}
	if rp := s.resourcePriorityFor(groupURI); rp != "" {
		headers = append(headers, header{"Resource-Priority", rp})
	}
	if contentType != "" {
		headers = append(headers, header{"Content-Type", contentType})
	}
	s.respond(send, msg, 200, "OK", headers, body)
	return true
}

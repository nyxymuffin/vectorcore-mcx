package sip

import (
	"context"
	"strings"

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

// groupPriorityState returns the in-progress emergency/imminent-peril state
// of a group: "emergency", "imminent" or "".
func (s *Server) groupPriorityState(groupURI string) string {
	if v, ok := s.inProgressPriority.Load(strings.ToLower(strings.TrimSpace(groupURI))); ok {
		return v.(string)
	}
	return ""
}

func (s *Server) setGroupPriorityState(groupURI, state string) {
	key := strings.ToLower(strings.TrimSpace(groupURI))
	if state == "" {
		s.inProgressPriority.Delete(key)
		return
	}
	s.inProgressPriority.Store(key, state)
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

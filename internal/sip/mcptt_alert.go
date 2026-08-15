package sip

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// MCPTT emergency alert, TS 24.379 clause 12.1: a standalone SIP MESSAGE
// whose mcptt-info carries <alert-ind>. The controlling function authorises
// it (clause 6.3.3.1.13.1 - the user-profile and group-document rulesets are
// stood in for by the same allow_emergency_call flags the emergency call
// path uses), notifies the other affiliated members (clause 6.3.3.1.11),
// caches the outstanding alert, and confirms receipt back to the originator
// (clause 6.3.3.1.20 with <alert-ind-rcvd>).

// alertState tracks outstanding alerts: group URI → originator → raised at.
type alertState struct {
	mu     sync.Mutex
	alerts map[string]map[string]time.Time
}

func newAlertState() *alertState {
	return &alertState{alerts: map[string]map[string]time.Time{}}
}

func (a *alertState) raise(group, user string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	group, user = strings.ToLower(group), strings.ToLower(user)
	if a.alerts[group] == nil {
		a.alerts[group] = map[string]time.Time{}
	}
	a.alerts[group][user] = time.Now().UTC()
}

// cancel clears one originator's alert; reports whether it existed.
func (a *alertState) cancel(group, user string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	group, user = strings.ToLower(group), strings.ToLower(user)
	if _, ok := a.alerts[group][user]; !ok {
		return false
	}
	delete(a.alerts[group], user)
	if len(a.alerts[group]) == 0 {
		delete(a.alerts, group)
	}
	return true
}

func mcpttInfoOf(msg *Message) string {
	if part := msg.Part("application/vnd.3gpp.mcptt-info+xml"); part != nil {
		return string(part.Body)
	}
	if strings.Contains(strings.ToLower(msg.Header("Content-Type")), "mcptt-info") {
		return string(msg.Body)
	}
	return ""
}

// handleMcpttAlertMessage implements the controlling side of clause 12.1.3
// for a SIP MESSAGE carrying an <alert-ind>.
func (s *Server) handleMcpttAlertMessage(ctx context.Context, send responder, msg *Message, source string) {
	info := mcpttInfoOf(msg)
	groupURI := mcpttIdentityFromBody(msg)
	originator := strings.TrimSpace(xmlElementText(xmlElementBody(info, "mcptt-calling-user-id"), "mcpttURI"))
	if originator == "" {
		originator = identityFrom(msg)
	}
	alertTrue := mcpttInfoFlagTrue(msg, "alert-ind")

	slog.Info("MCPTT emergency alert MESSAGE", "group", groupURI, "originator", originator,
		"alert", alertTrue, "source", source)

	group := s.groupByURI(ctx, groupURI)
	if group == nil {
		s.respond(send, msg, 404, "Not Found",
			[]header{s.mcpttWarning("163 the group identity indicated in the request does not exist")}, nil)
		return
	}

	if !alertTrue {
		// Clause 12.1.3.2: cancellation. A user may always cancel their own
		// alert (clause 6.3.3.1.13.3 - cancelling another user's alert needs
		// an authority the profile model does not carry yet).
		if !s.emergencyAlerts.cancel(groupURI, originator) {
			// No outstanding alert from this user on this group.
			s.respond(send, msg, 404, "Not Found", nil, nil)
			return
		}
		s.notifyAlertToMembers(ctx, group, groupURI, originator, false)
		s.respond(send, msg, 200, "OK", nil, nil)
		slog.Info("MCPTT emergency alert cancelled", "group", groupURI, "originator", originator)
		return
	}

	// Clause 12.1.3.1 step 4 a: authorisation per 6.3.3.1.13.1.
	if !s.emergencyCallAuthorised(ctx, originator, group) {
		body := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
			`<alert-ind>false</alert-ind></mcptt-Params></mcpttinfo>`
		s.respond(send, msg, 403, "Forbidden",
			[]header{{"Content-Type", "application/vnd.3gpp.mcptt-info+xml"}}, []byte(body))
		return
	}

	// Step 4 b i: affiliation, with implicit affiliation for eligible members
	// (clauses 9.2.2.3.6/9.2.2.3.7, eligibility stood in for by membership).
	userID, groupID, ok := s.userGroupIDs(ctx, originator, groupURI)
	if !ok {
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("120 user is not affiliated to this group")}, nil)
		return
	}
	affiliated, _ := s.st.IsGroupAffiliated(ctx, userID, groupID)
	if !affiliated {
		member, _ := s.st.IsGroupMember(ctx, userID, groupID)
		if !member {
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("120 user is not affiliated to this group")}, nil)
			return
		}
		if _, err := s.st.CreateGroupAffiliation(ctx, store.GroupAffiliation{
			UserID: userID, GroupID: groupID, State: "affiliated",
		}); err != nil {
			slog.Warn("alert implicit affiliation failed", "err", err)
		}
	}

	// Step 4 b ii: notify the other affiliated members; step 4 b iii A: cache
	// the outstanding alert.
	s.emergencyAlerts.raise(groupURI, originator)
	s.notifyAlertToMembers(ctx, group, groupURI, originator, true)

	// Steps 4 b iii-iv: 200 to the originator.
	s.respond(send, msg, 200, "OK", nil, nil)

	// Steps 4 b v-vi: the clause 6.3.3.1.20 receipt confirmation back to the
	// originating user, with <alert-ind-rcvd>.
	clientID := strings.TrimSpace(xmlElementText(info, "mcptt-client-id"))
	s.sendAlertReceipt(ctx, originator, groupURI, clientID)
}

// notifyAlertToMembers sends the clause 6.3.3.1.11 SIP MESSAGE to every
// affiliated registered member other than the originator, with <alert-ind>
// reflecting the new state.
func (s *Server) notifyAlertToMembers(ctx context.Context, group *store.Group, groupURI, originator string, alert bool) {
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
		affiliated, _ := s.st.IsGroupAffiliated(ctx, m.UserID, group.ID)
		if !affiliated {
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
				`<alert-ind>%t</alert-ind>`+
				`</mcptt-Params></mcpttinfo>`,
			impu, originator, groupURI, alert)
		s.sendMcpttMessage(ctx, impu, body)
	}
}

// sendAlertReceipt is the clause 6.3.3.1.20 confirmation toward the alert
// originator: alert-ind true plus alert-ind-rcvd true.
func (s *Server) sendAlertReceipt(ctx context.Context, originator, groupURI, clientID string) {
	body := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		fmt.Sprintf(`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`, originator) +
		fmt.Sprintf(`<mcptt-calling-group-id><mcpttURI>%s</mcpttURI></mcptt-calling-group-id>`, groupURI) +
		`<alert-ind>true</alert-ind><alert-ind-rcvd>true</alert-ind-rcvd>`
	if clientID != "" {
		body += fmt.Sprintf(`<mcptt-client-id>%s</mcptt-client-id>`, clientID)
	}
	body += `</mcptt-Params></mcpttinfo>`
	s.sendMcpttMessage(ctx, originator, body)
}

// sendMcpttMessage delivers an MCPTT notification MESSAGE to a served user's
// registered contact per clause 6.3.3.1.11: the MCPTT feature tags in
// Accept-Contact, the PSI asserted, the MCPTT ICSI in P-Asserted-Service.
func (s *Server) sendMcpttMessage(ctx context.Context, targetImpu, infoBody string) {
	s.sendMcpttMessageRaw(ctx, targetImpu, infoBody, "application/vnd.3gpp.mcptt-info+xml")
}

func (s *Server) sendMcpttMessageRaw(ctx context.Context, targetImpu, body, contentType string) {
	regs, err := s.st.ListRegistrations(ctx)
	if err != nil {
		return
	}
	var reg *store.Registration
	for _, r := range regs {
		if r.Registered && strings.EqualFold(strings.TrimSpace(r.PublicIdentity), strings.TrimSpace(targetImpu)) {
			candidate := r
			reg = &candidate
			break
		}
	}
	if reg == nil {
		slog.Info("MCPTT notification target not registered", "target", targetImpu)
		return
	}
	transport := strings.ToLower(strings.TrimSpace(reg.Transport))
	if transport == "" {
		transport = "udp"
	}
	target := ""
	if reg.SourceIP != "" {
		port := reg.SourcePort
		if port == 0 {
			port = 5060
		}
		target = net.JoinHostPort(reg.SourceIP, strconv.Itoa(port))
	}
	if target == "" {
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
		{"Accept-Contact", "*;+g.3gpp.mcptt;require;explicit"},
		{"Accept-Contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt";require;explicit`},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"P-Asserted-Service", "urn:urn-7:3gpp-service.ims.icsi.mcptt"},
		{"Content-Type", contentType},
	}
	out := buildRequest("MESSAGE", targetImpu, hdrs, []byte(body))
	slog.Info("MCPTT notification MESSAGE sending", "target", targetImpu, "addr", target)
	s.sendTransacted(ctx, transport, target, branch, "MESSAGE", []byte(out))
}

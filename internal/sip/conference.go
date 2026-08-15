package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Conference event package, TS 24.379 clause 10.1.3: a session participant
// subscribes with Event: conference toward the session, and the controlling
// function notifies the participant list as application/conference-info+xml
// (RFC 4575) alongside an mcptt-info body naming the group (clause 6.3.3.4).
// Notifications re-fire when the participant set changes.

type confSub struct {
	sub      store.Subscription
	groupURI string
}

type conferenceSubs struct {
	mu   sync.Mutex
	subs map[string]confSub // sub.CallID → subscription
}

func newConferenceSubs() *conferenceSubs {
	return &conferenceSubs{subs: map[string]confSub{}}
}

// conferenceGroupURI resolves the group of a conference SUBSCRIBE: the
// <mcptt-request-uri> of the mcptt-info body (clause 10.1.3.2 step 8).
func conferenceGroupURI(msg *Message) string {
	return strings.TrimSpace(mcpttIdentityFromBody(msg))
}

// isSessionParticipant reports whether a user is currently a participant of
// the group session (clause 10.1.3.4.1 condition 1 a i).
func (s *Server) isSessionParticipant(ctx context.Context, groupURI, userURI string) bool {
	peers, err := s.st.ListCallsByGroup(ctx, groupURI)
	if err != nil {
		return false
	}
	for _, call := range peers {
		if strings.EqualFold(s.legUserOf(call), strings.TrimSpace(userURI)) {
			return true
		}
	}
	return false
}

// legUserOf mirrors the media observer's leg-user resolution: the initiator
// on client-originated legs, the target on AS-initiated ones.
func (s *Server) legUserOf(call store.MCPTTCall) string {
	if strings.EqualFold(strings.TrimSpace(call.InitiatorURI), strings.TrimSpace(s.cfg.MCX.SIPIdentity)) {
		return strings.TrimSpace(call.TargetURI)
	}
	return strings.TrimSpace(call.InitiatorURI)
}

// conferenceInfoBody builds the RFC 4575 document of clause 6.3.3.4: the
// group ID as the conference entity and one <user> per session participant.
func (s *Server) conferenceInfoBody(ctx context.Context, groupURI string, version int) string {
	peers, _ := s.st.ListCallsByGroup(ctx, groupURI)
	var users strings.Builder
	seen := map[string]bool{}
	count := 0
	for _, call := range peers {
		user := s.legUserOf(call)
		if user == "" || seen[strings.ToLower(user)] {
			continue
		}
		seen[strings.ToLower(user)] = true
		count++
		fmt.Fprintf(&users, `
    <user entity="%s">
      <endpoint entity="%s">
        <status>connected</status>
      </endpoint>
    </user>`, user, user)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="%s" state="full" version="%d">
  <conference-state>
    <user-count>%d</user-count>
  </conference-state>
  <users>%s
  </users>
</conference-info>`, groupURI, version, count, users.String())
}

// conferenceNotifyBody is the multipart NOTIFY payload of clause 6.3.3.4:
// the mcptt-info naming group and target, plus the conference-info document.
func (s *Server) conferenceNotifyBody(ctx context.Context, sub store.Subscription, groupURI string, version int) ([]byte, string) {
	info := fmt.Sprintf(
		`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
			`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
			`<mcptt-calling-group-id><mcpttURI>%s</mcpttURI></mcptt-calling-group-id>`+
			`</mcptt-Params></mcpttinfo>`,
		sub.SubscriberURI, groupURI)
	conf := s.conferenceInfoBody(ctx, groupURI, version)
	const boundary = "mcxasconf"
	body := fmt.Sprintf(
		"--%s\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Type: application/conference-info+xml\r\n\r\n%s\r\n--%s--\r\n",
		boundary, info, boundary, conf, boundary)
	return []byte(body), fmt.Sprintf(`multipart/mixed;boundary="%s"`, boundary)
}

// registerConferenceSubscription tracks or drops a conference subscription.
func (s *Server) registerConferenceSubscription(sub store.Subscription, groupURI string, expires int) {
	s.confSubs.mu.Lock()
	defer s.confSubs.mu.Unlock()
	if expires == 0 {
		delete(s.confSubs.subs, sub.CallID)
		return
	}
	s.confSubs.subs[sub.CallID] = confSub{sub: sub, groupURI: groupURI}
}

// NotifyConferenceChange re-notifies every subscriber of a group whose
// participant set changed (clause 10.1.3.4.2: notifications on state
// changes).
func (s *Server) NotifyConferenceChange(groupURI string) {
	if strings.TrimSpace(groupURI) == "" {
		return
	}
	s.confSubs.mu.Lock()
	var targets []confSub
	for _, cs := range s.confSubs.subs {
		if strings.EqualFold(strings.TrimSpace(cs.groupURI), strings.TrimSpace(groupURI)) {
			targets = append(targets, cs)
		}
	}
	s.confSubs.mu.Unlock()
	if len(targets) == 0 {
		return
	}
	ctx := context.Background()
	for _, cs := range targets {
		subscribe, err := synthesizeSubscribe(cs.sub)
		if err != nil {
			continue
		}
		if err := s.sendNotify(ctx, cs.sub, subscribe, nil); err != nil {
			slog.Warn("conference change notify failed", "call_id", cs.sub.CallID, "err", err)
		} else {
			slog.Info("conference change notify sent", "call_id", cs.sub.CallID,
				"group_uri", groupURI, "subscriber", cs.sub.SubscriberURI)
		}
	}
}

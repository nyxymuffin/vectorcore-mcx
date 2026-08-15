package sip

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// emergencyInvite is a group INVITE whose mcptt-info carries an emergency or
// imminent peril indication (TS 24.379 clause 6.3.3.1.13.2 territory).
func emergencyInvite(callID, indication string) string {
	info := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		`<` + indication + `>true</` + indication + `>` +
		`</mcptt-Params></mcpttinfo>`
	sdp := "v=0\r\n" +
		"o=ue 1 1 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=application 49172 udp MCPTT\r\n" +
		"a=fmtp:MCPTT mc_implicit_request\r\n"
	body := "--emg\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + info +
		"\r\n--emg\r\nContent-Type: application/sdp\r\n\r\n" + sdp +
		"\r\n--emg--\r\n"
	return "INVITE sip:test_group@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:test_group@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:caller@198.51.100.116:5060>\r\n" +
		`Content-Type: multipart/mixed;boundary="emg"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

// allowEmergency flips the provisioning stand-ins for the fixture's caller
// and group.
func allowEmergency(t *testing.T, st interface {
	ListUsers(context.Context) ([]store.User, error)
	UpdateUser(context.Context, string, store.User) (*store.User, error)
	ListGroups(context.Context) ([]store.Group, error)
	UpdateGroup(context.Context, string, store.Group) (*store.Group, error)
}, user, group bool) {
	t.Helper()
	ctx := context.Background()
	users, _ := st.ListUsers(ctx)
	for _, u := range users {
		u.AllowEmergencyCall = user
		if _, err := st.UpdateUser(ctx, u.ID, u); err != nil {
			t.Fatal(err)
		}
	}
	groups, _ := st.ListGroups(ctx)
	for _, g := range groups {
		g.AllowEmergencyCall = group
		if _, err := st.UpdateGroup(ctx, g.ID, g); err != nil {
			t.Fatal(err)
		}
	}
}

// An unauthorised emergency call is 403 with the clause 6.3.3.1.14 body:
// mcptt-info negating the emergency and alert indications.
func TestEmergencyCallUnauthorisedGets403WithNegatedIndications(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, false, false)

	responses := collectResponses(t, s, emergencyInvite("emg-403", "emergency-ind"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
	for _, want := range []string{
		"Content-Type: application/vnd.3gpp.mcptt-info+xml",
		"<emergency-ind>false</emergency-ind>",
		"<alert-ind>false</alert-ind>",
	} {
		if !strings.Contains(responses[0], want) {
			t.Fatalf("403 missing %q:\n%s", want, responses[0])
		}
	}
}

// A user allowed by profile but a group that disallows emergency calls is
// still refused (the <allow-MCPTT-emergency-call> group condition).
func TestEmergencyCallGroupDisallowedGets403(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, true, false)

	responses := collectResponses(t, s, emergencyInvite("emg-403g", "emergency-ind"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
}

// An authorised emergency call is accepted, puts the group in the in-progress
// emergency state, and the member legs carry the emergency Resource-Priority
// (clause 6.3.3.1.19).
func TestEmergencyCallAcceptedSetsStateAndResourcePriority(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, true, true)
	ctx := context.Background()

	// A second member on a capture socket to observe the leg's headers.
	member, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:member2@example.test", MCPTTID: "sip:member2@example.test", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	groups, _ := st.ListGroups(ctx)
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
		UserID: member.ID, GroupID: groups[0].ID, Role: "MCPTT User",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{
		UserID: member.ID, GroupID: groups[0].ID, State: "affiliated",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPublishedState(ctx, store.PublishedState{
		UserURI: "sip:member2@example.test", Event: "poc-settings",
		Body: `<poc-settings><entity id="m"><am-settings><answer-mode>automatic</answer-mode></am-settings></entity></poc-settings>`,
	}); err != nil {
		t.Fatal(err)
	}
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	_, portStr, _ := net.SplitHostPort(sock.LocalAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: "sip:member2@example.test", Registered: true,
		ContactURI: "sip:member2@127.0.0.1:" + portStr,
		SourceIP:   "127.0.0.1", SourcePort: port, Transport: "udp",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	responses := collectResponses(t, s, emergencyInvite("emg-ok", "emergency-ind"))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}
	if got := s.groupPriorityState("sip:test_group@example.test"); got != "emergency" {
		t.Fatalf("in-progress state = %q, want emergency", got)
	}

	_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, _, err := sock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("member leg never arrived: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "Resource-Priority: mcptt.0\r\n") {
		t.Fatalf("member leg lacks the emergency Resource-Priority:\n%s", buf[:n])
	}
}

// A Resource-Priority header claiming emergency without the indication and
// without an in-progress emergency state is refused (step 9).
func TestUnearnedResourcePriorityGets403(t *testing.T) {
	s, _ := groupCallFixture(t)

	raw := strings.Replace(snapshotGroupInvite("emg-rp"),
		"Max-Forwards: 70\r\n",
		"Max-Forwards: 70\r\nResource-Priority: mcptt.0\r\n", 1)
	responses := collectResponses(t, s, raw)
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
}

// An imminent peril indication yields the imminent state and mcptt.1 legs;
// an emergency overrides it.
func TestImminentPerilStateAndEmergencyOverride(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, true, true)

	responses := collectResponses(t, s, emergencyInvite("imm-ok", "imminentperil-ind"))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}
	if got := s.groupPriorityState("sip:test_group@example.test"); got != "imminent" {
		t.Fatalf("state = %q, want imminent", got)
	}

	responses = collectResponses(t, s, emergencyInvite("emg-after-imm", "emergency-ind"))
	if len(responses) != 3 {
		t.Fatalf("emergency upgrade failed: %v", responses)
	}
	if got := s.groupPriorityState("sip:test_group@example.test"); got != "emergency" {
		t.Fatalf("state = %q, want emergency after upgrade", got)
	}
}

// TNG2 (clause 6.3.3.1.16): the in-progress emergency state expires after
// the configured group time limit and the group returns to normal priority.
func TestTNG2ExpiresInProgressEmergencyState(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, true, true)
	s.cfg.SIP.Emergency.GroupTimeLimitSeconds = 1

	responses := collectResponses(t, s, emergencyInvite("tng2-1", "emergency-ind"))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}
	if got := s.groupPriorityState("sip:test_group@example.test"); got != "emergency" {
		t.Fatalf("state = %q, want emergency", got)
	}

	time.Sleep(1100 * time.Millisecond)
	if got := s.groupPriorityState("sip:test_group@example.test"); got != "" {
		t.Fatalf("state = %q, want cleared after TNG2 expiry", got)
	}
}

// With the limit disabled (0) the emergency state persists.
func TestTNG2DisabledKeepsEmergencyState(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, true, true)
	s.cfg.SIP.Emergency.GroupTimeLimitSeconds = 0

	responses := collectResponses(t, s, emergencyInvite("tng2-off", "emergency-ind"))
	if len(responses) != 3 {
		t.Fatalf("responses = %v", responses)
	}
	time.Sleep(50 * time.Millisecond)
	if got := s.groupPriorityState("sip:test_group@example.test"); got != "emergency" {
		t.Fatalf("state = %q, want emergency to persist without TNG2", got)
	}
}

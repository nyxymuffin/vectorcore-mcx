package sip

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

func pesInvite(callID string) string {
	sdp := "v=0\r\n" +
		"o=ue 1 1 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=application 49172 udp MCPTT\r\n"
	return "INVITE sip:mcptt-pes@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-pes@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:caller@198.51.100.116:5060>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + fmt.Sprint(len(sdp)) + "\r\n\r\n" + sdp
}

// Establishment per clause 8.2.2: 200 with the session URI in Contact,
// norefersub supported, the PSI asserted, and an SDP answer.
func TestPreEstablishedSessionEstablishment(t *testing.T) {
	s, _ := groupCallFixture(t)

	responses := collectResponses(t, s, pesInvite("pes-1"))
	last := responses[len(responses)-1]
	if !strings.HasPrefix(last, "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 200", responses)
	}
	for _, want := range []string{
		"Contact: <sip:mcptt-pes-",
		"Supported: norefersub, timer",
		"P-Asserted-Identity: <sip:mcptt-as@",
		"m=audio 40000",
	} {
		if !strings.Contains(last, want) {
			t.Fatalf("200 missing %q:\n%s", want, last)
		}
	}
}

// A REFER on the session originates the group call: 200 with
// Refer-Sub: false, and the member leg goes out with the session's SDP
// (clause 10.1.1.3.1.2).
func TestReferOriginatesGroupCallOverPreEstablishedSession(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()

	// A second affiliated member on a capture socket.
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
	sock := registerAtSocket(t, st, "sip:member2@example.test")

	if r := collectResponses(t, s, pesInvite("pes-2")); !strings.HasPrefix(r[len(r)-1], "SIP/2.0 200") {
		t.Fatalf("establishment failed: %v", r)
	}

	refer := "REFER sip:mcptt-pes@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKpesrefer\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-pes@example.test>;tag=x\r\n" +
		"Call-ID: pes-2\r\n" +
		"CSeq: 2 REFER\r\n" +
		"Refer-To: <sip:test_group@example.test>\r\n" +
		"Refer-Sub: false\r\n" +
		"Content-Length: 0\r\n\r\n"
	responses := collectResponses(t, s, refer)
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("REFER responses = %v, want 200", responses)
	}
	if !strings.Contains(responses[0], "Refer-Sub: false") {
		t.Fatalf("200 lacks Refer-Sub: false:\n%s", responses[0])
	}

	// The member leg fires, carrying the group id.
	buf := make([]byte, 8192)
	_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := sock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("member leg never fired after REFER: %v", err)
	}
	leg := string(buf[:n])
	if !strings.Contains(leg, "INVITE sip:member2@example.test") ||
		!strings.Contains(leg, "sip:test_group@example.test") {
		t.Fatalf("member leg incomplete:\n%s", leg)
	}

	// The session's call record joined the group for the media relay.
	call, _ := st.GetCall(ctx, "pes-2")
	if call == nil || call.GroupURI != "sip:test_group@example.test" {
		t.Fatalf("pes call record not joined to the group: %+v", call)
	}
}

// A REFER naming a group the owner may not call is refused with the
// admission verdict (here: not affiliated, warning 120).
func TestReferAdmissionRefusal(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()
	if _, err := st.CreateGroup(ctx, store.Group{URI: "sip:other_group@example.test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if r := collectResponses(t, s, pesInvite("pes-3")); !strings.HasPrefix(r[len(r)-1], "SIP/2.0 200") {
		t.Fatalf("establishment failed: %v", r)
	}
	refer := "REFER sip:mcptt-pes@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKpesref403\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-pes@example.test>;tag=x\r\n" +
		"Call-ID: pes-3\r\n" +
		"CSeq: 2 REFER\r\n" +
		"Refer-To: <sip:other_group@example.test>\r\n" +
		"Content-Length: 0\r\n\r\n"
	responses := collectResponses(t, s, refer)
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want 403", responses)
	}
	if !strings.Contains(responses[0], `"120 user is not affiliated to this group"`) {
		t.Fatalf("403 lacks warning 120:\n%s", responses[0])
	}
}

// A REFER outside any pre-established dialog is 481.
func TestReferWithoutSessionIs481(t *testing.T) {
	s, _ := groupCallFixture(t)
	refer := "REFER sip:mcptt-pes@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKpesnone\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-pes@example.test>;tag=x\r\n" +
		"Call-ID: no-such-pes\r\n" +
		"CSeq: 1 REFER\r\n" +
		"Refer-To: <sip:test_group@example.test>\r\n" +
		"Content-Length: 0\r\n\r\n"
	responses := collectResponses(t, s, refer)
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 481") {
		t.Fatalf("responses = %v, want 481", responses)
	}
}

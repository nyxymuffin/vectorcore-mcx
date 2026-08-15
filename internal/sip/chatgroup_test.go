package sip

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

// Chat group calls, TS 24.379 clause 10.1.2: members join by INVITEing the
// group; the controlling function creates or joins the chat session and does
// not fan out to other members.

func chatFixture(t *testing.T) (*Server, *sqlite.Store, store.Group) {
	t.Helper()
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Default()
	cfg.Media.AdvertiseHost = "192.0.2.54"
	s := NewServer(cfg, st)
	s.timerT1Override = 10 * time.Millisecond

	ctx := context.Background()
	group, err := st.CreateGroup(ctx, store.Group{
		URI: "sip:chat_group@example.test", Enabled: true, ChatGroup: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, impu := range []string{"sip:caller@example.test", "sip:member2@example.test"} {
		u, err := st.CreateUser(ctx, store.User{IMPU: impu, MCPTTID: impu, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
			UserID: u.ID, GroupID: group.ID, Role: "MCPTT User",
		}); err != nil {
			t.Fatal(err)
		}
	}
	return s, st, group
}

func chatInvite(callID, from string) string {
	sdp := "v=0\r\n" +
		"o=ue 1 1 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=application 49172 udp MCPTT\r\n" +
		"a=fmtp:MCPTT mc_implicit_request\r\n"
	return "INVITE sip:chat_group@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <" + from + ">;tag=from1\r\n" +
		"To: <sip:chat_group@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <" + from + ">\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + fmt.Sprint(len(sdp)) + "\r\n\r\n" + sdp
}

var reSessionURI = regexp.MustCompile(`sip:mcptt-session-[0-9a-f]+@[^;>]+`)

// A member without prior affiliation joins the chat group: implicit
// affiliation (clause 10.1.2.4.1.1 step 6 / 9.2.2.3.7) instead of 403 "120",
// and no fan-out to the other member.
func TestChatGroupJoinImplicitlyAffiliatesAndDoesNotFanOut(t *testing.T) {
	s, st, group := chatFixture(t)
	ctx := context.Background()

	// The other member is registered at a capture socket; it must NOT be
	// invited.
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
	if _, err := st.UpsertPublishedState(ctx, store.PublishedState{
		UserURI: "sip:member2@example.test", Event: "poc-settings",
		Body: `<poc-settings><entity id="m"><am-settings><answer-mode>automatic</answer-mode></am-settings></entity></poc-settings>`,
	}); err != nil {
		t.Fatal(err)
	}

	responses := collectResponses(t, s, chatInvite("chat-1", "sip:caller@example.test"))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}

	// Implicit affiliation recorded.
	affs, err := st.ListGroupAffiliations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range affs {
		if a.GroupID == group.ID && a.State == "affiliated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no implicit affiliation recorded: %+v", affs)
	}

	// No fan-out to the registered member.
	_ = sock.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 4096)
	if n, _, err := sock.ReadFrom(buf); err == nil {
		t.Fatalf("chat group fanned out an INVITE:\n%s", buf[:n])
	}
}

// Two joiners of the same chat session share one session identity (clause
// 10.1.2.4.1.1 step 11 a); after the last leg ends the next call is a new
// session with a new identity.
func TestChatGroupJoinersShareSessionIdentity(t *testing.T) {
	s, _, _ := chatFixture(t)

	r1 := collectResponses(t, s, chatInvite("chat-s1", "sip:caller@example.test"))
	r2 := collectResponses(t, s, chatInvite("chat-s2", "sip:member2@example.test"))
	if len(r1) != 3 || len(r2) != 3 {
		t.Fatalf("expected both joins to complete: %d/%d responses", len(r1), len(r2))
	}
	id1 := reSessionURI.FindString(r1[2])
	id2 := reSessionURI.FindString(r2[2])
	if id1 == "" || id1 != id2 {
		t.Fatalf("session identities differ: %q vs %q", id1, id2)
	}

	// End both legs; the next join gets a fresh identity.
	for _, leg := range []struct {
		callID, from, toTag string
	}{
		{"chat-s1", "sip:caller@example.test", tagFromResponse(r1[2])},
		{"chat-s2", "sip:member2@example.test", tagFromResponse(r2[2])},
	} {
		bye := "BYE sip:mcptt-as@example.test SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKbye" + leg.callID + "\r\n" +
			"From: <" + leg.from + ">;tag=from1\r\n" +
			"To: <sip:chat_group@example.test>;tag=" + leg.toTag + "\r\n" +
			"Call-ID: " + leg.callID + "\r\n" +
			"CSeq: 2 BYE\r\n" +
			"Content-Length: 0\r\n\r\n"
		byeResp := collectResponses(t, s, bye)
		if len(byeResp) == 0 || !strings.HasPrefix(byeResp[len(byeResp)-1], "SIP/2.0 200") {
			t.Fatalf("BYE for %s not accepted: %v", leg.callID, byeResp)
		}
	}

	r3 := collectResponses(t, s, chatInvite("chat-s3", "sip:caller@example.test"))
	if len(r3) != 3 {
		t.Fatalf("rejoin failed: %v", r3)
	}
	id3 := reSessionURI.FindString(r3[2])
	if id3 == "" || id3 == id1 {
		t.Fatalf("new chat session reused the old identity %q", id1)
	}
}

// A non-member is still refused (membership is the implicit-affiliation
// eligibility stand-in, clause 9.2.2.3.6).
func TestChatGroupNonMemberRefused(t *testing.T) {
	s, st, _ := chatFixture(t)
	if _, err := st.CreateUser(context.Background(), store.User{
		IMPU: "sip:outsider@example.test", MCPTTID: "sip:outsider@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	responses := collectResponses(t, s, chatInvite("chat-403", "sip:outsider@example.test"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
}

func tagFromResponse(resp string) string {
	to := headerLine(resp, "To")
	if i := strings.Index(to, "tag="); i >= 0 {
		return to[i+4:]
	}
	return ""
}

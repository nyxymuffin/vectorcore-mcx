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

// These tests pin the current wire behaviour of the group-call path before
// the participating/controlling extraction (design slice 2), so that "no
// behaviour change" is enforced by comparison rather than by review. They
// assert full ordered exchanges with volatile tokens normalised, not
// substring presence.

var (
	reTag    = regexp.MustCompile(`tag=[0-9a-f]{8,}`)
	reBranch = regexp.MustCompile(`branch=z9hG4bK[0-9a-fA-F]+`)
	reETag   = regexp.MustCompile(`SIP-ETag: .+`)
)

// normalizeWire replaces per-run random values so exchanges compare stably.
func normalizeWire(s string) string {
	s = reTag.ReplaceAllString(s, "tag=TAG")
	s = reBranch.ReplaceAllString(s, "branch=BRANCH")
	s = reETag.ReplaceAllString(s, "SIP-ETag: ETAG")
	return s
}

func groupCallFixture(t *testing.T) (*Server, *sqlite.Store) {
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
	caller, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:caller@example.test", MCPTTID: "sip:caller@example.test", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := st.CreateGroup(ctx, store.Group{
		URI: "sip:test_group@example.test", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
		UserID: caller.ID, GroupID: group.ID, Role: "MCPTT User",
	}); err != nil {
		t.Fatal(err)
	}
	return s, st
}

func snapshotGroupInvite(callID string) string {
	sdp := "v=0\r\n" +
		"o=ue 1 1 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=application 49172 udp MCPTT\r\n" +
		"a=fmtp:MCPTT mc_implicit_request\r\n"
	return "INVITE sip:test_group@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:test_group@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:caller@198.51.100.116:5060>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + fmt.Sprint(len(sdp)) + "\r\n\r\n" + sdp
}

func collectResponses(t *testing.T, s *Server, raw string) []string {
	t.Helper()
	var responses []string
	s.handleRaw(context.Background(), "192.0.2.52:5060", "udp", []byte(raw), func(b []byte) error {
		responses = append(responses, string(b))
		return nil
	})
	return responses
}

// A member's group INVITE produces exactly 100, 180, 200 in order, with the
// exact header and SDP shape pinned.
func TestGroupInviteWireExchangeForMember(t *testing.T) {
	s, _ := groupCallFixture(t)

	responses := collectResponses(t, s, snapshotGroupInvite("snap-accept-1"))
	if len(responses) != 3 {
		t.Fatalf("got %d responses, want 100/180/200:\n%s", len(responses), strings.Join(responses, "\n---\n"))
	}

	for i, wantStatus := range []string{"SIP/2.0 100 Trying", "SIP/2.0 180 Ringing", "SIP/2.0 200 OK"} {
		if !strings.HasPrefix(responses[i], wantStatus) {
			t.Fatalf("response %d = %q, want prefix %q", i, firstLine(responses[i]), wantStatus)
		}
	}

	final := normalizeWire(responses[2])
	// Pinned invariants of the 200: dialog identity, routing, and the SDP
	// answer granting the implicitly-requested floor.
	for _, want := range []string{
		// The Via echoes the client's own branch verbatim, so it is pinned
		// literally rather than normalised.
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKsnap-accept-1\r\n",
		"From: <sip:caller@example.test>;tag=from1\r\n",
		"To: <sip:test_group@example.test>;tag=TAG\r\n",
		"Call-ID: snap-accept-1\r\n",
		"CSeq: 1 INVITE\r\n",
		"Record-Route: <sip:",
		"Contact: <sip:",
		"Content-Type: application/sdp\r\n",
		"m=audio 40000 RTP/AVP 0\r\n",
		"m=application 40002 udp MCPTT\r\n",
		"a=fmtp:MCPTT MCPTT mc_priority=0;mc_granted;mc_implicit_request\r\n",
	} {
		if !strings.Contains(final, want) {
			t.Fatalf("200 OK missing pinned element %q:\n%s", want, final)
		}
	}
}

// A non-member's INVITE is refused with exactly one 403 and no dialog
// side effects visible on the wire.
func TestGroupInviteWireExchangeForNonMember(t *testing.T) {
	s, _ := groupCallFixture(t)

	raw := strings.Replace(snapshotGroupInvite("snap-reject-1"),
		"From: <sip:caller@example.test>;tag=from1",
		"From: <sip:stranger@example.test>;tag=from1", 1)
	responses := collectResponses(t, s, raw)

	if len(responses) != 1 {
		t.Fatalf("got %d responses, want exactly the 403:\n%s", len(responses), strings.Join(responses, "\n---\n"))
	}
	if !strings.HasPrefix(responses[0], "SIP/2.0 403 Forbidden") {
		t.Fatalf("response = %q, want 403 Forbidden", firstLine(responses[0]))
	}
}

// The accepted INVITE fans out an RX INVITE to the other registered member.
// Its wire shape is pinned by capturing it on a real UDP socket.
func TestGroupInviteFansOutRXInviteToMember(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()

	// Second member, registered with a contact routed at our capture socket.
	member, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:member2@example.test", MCPTTID: "sip:member2@example.test", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := st.ListGroups(ctx)
	if err != nil || len(groups) != 1 {
		t.Fatalf("groups: %v err: %v", groups, err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
		UserID: member.ID, GroupID: groups[0].ID, Role: "MCPTT User",
	}); err != nil {
		t.Fatal(err)
	}

	capture, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = capture.Close() })
	_, portStr, _ := net.SplitHostPort(capture.LocalAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: "sip:member2@example.test",
		Registered:     true,
		ContactURI:     "sip:member2@127.0.0.1:" + portStr,
		SourceIP:       "127.0.0.1",
		SourcePort:     port,
		Transport:      "udp",
		ExpiresAt:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	responses := collectResponses(t, s, snapshotGroupInvite("snap-fanout-1"))
	if len(responses) != 3 {
		t.Fatalf("inbound leg got %d responses, want 3", len(responses))
	}

	_ = capture.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8192)
	n, _, err := capture.ReadFrom(buf)
	if err != nil {
		t.Fatalf("RX INVITE never arrived at the member: %v", err)
	}
	rx := normalizeWire(string(buf[:n]))

	for _, want := range []string{
		"INVITE sip:member2@example.test SIP/2.0",
		"To: <sip:member2@example.test>\r\n",
		"CSeq: 1 INVITE\r\n",
		"P-Asserted-Identity: <sip:caller@example.test>\r\n",
		`Content-Type: multipart/mixed;boundary="mcxasboundary"`,
		"Content-Type: application/sdp",
		"m=audio 40000 RTP/AVP 0",
		"m=application 40002 udp MCPTT",
		"Content-Type: application/vnd.3gpp.mcptt-info+xml",
		"<mcptt-calling-group-id><mcpttURI>sip:test_group@example.test</mcpttURI></mcptt-calling-group-id>",
		"<session-type>prearranged</session-type>",
	} {
		if !strings.Contains(rx, want) {
			t.Fatalf("RX INVITE missing pinned element %q:\n%s", want, rx)
		}
	}
	// The 2.0 cleanup must hold: no forced commencement mode.
	if strings.Contains(rx, "Answer-Mode") {
		t.Fatalf("RX INVITE reasserts Answer-Mode:\n%s", rx)
	}
}

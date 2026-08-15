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

// alertMessage builds a clause 12.1.1.1 emergency alert SIP MESSAGE.
func alertMessage(callID, groupURI, alertInd string) string {
	info := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		`<mcptt-request-uri><mcpttURI>` + groupURI + `</mcpttURI></mcptt-request-uri>` +
		`<mcptt-calling-user-id><mcpttURI>sip:caller@example.test</mcpttURI></mcptt-calling-user-id>` +
		`<mcptt-client-id>client-42</mcptt-client-id>` +
		`<alert-ind>` + alertInd + `</alert-ind>` +
		`</mcptt-Params></mcpttinfo>`
	return "MESSAGE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		"Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\";require;explicit\r\n" +
		"Content-Type: application/vnd.3gpp.mcptt-info+xml\r\n" +
		"Content-Length: " + fmt.Sprint(len(info)) + "\r\n\r\n" + info
}

// An authorised alert: members are notified with alert-ind true, the alert
// is cached, the originator gets 200 plus the 6.3.3.1.20 receipt with
// alert-ind-rcvd; cancellation notifies with alert-ind false.
func TestEmergencyAlertRaiseAndCancel(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, true, true)
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
	memberSock := registerAtSocket(t, st, "sip:member2@example.test")
	callerSock := registerAtSocket(t, st, "sip:caller@example.test")

	responses := collectResponses(t, s, alertMessage("alert-1", "sip:test_group@example.test", "true"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want exactly one 200", responses)
	}

	// The member's notification (6.3.3.1.11).
	notify := awaitDatagram(t, memberSock, "<alert-ind>true</alert-ind>")
	for _, want := range []string{
		"MESSAGE sip:member2@example.test SIP/2.0",
		"P-Asserted-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt",
		"<alert-ind>true</alert-ind>",
		"<mcptt-calling-user-id><mcpttURI>sip:caller@example.test</mcpttURI></mcptt-calling-user-id>",
		"<mcptt-calling-group-id><mcpttURI>sip:test_group@example.test</mcpttURI></mcptt-calling-group-id>",
	} {
		if !strings.Contains(notify, want) {
			t.Fatalf("alert notification missing %q:\n%s", want, notify)
		}
	}

	// The originator's receipt (6.3.3.1.20).
	receipt := awaitDatagram(t, callerSock, "<alert-ind-rcvd>true</alert-ind-rcvd>")
	for _, want := range []string{
		"<alert-ind-rcvd>true</alert-ind-rcvd>",
		"<mcptt-client-id>client-42</mcptt-client-id>",
	} {
		if !strings.Contains(receipt, want) {
			t.Fatalf("receipt missing %q:\n%s", want, receipt)
		}
	}

	// Cancellation (12.1.3.2): 200 and an alert-ind false notification.
	responses = collectResponses(t, s, alertMessage("alert-2", "sip:test_group@example.test", "false"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("cancel responses = %v, want 200", responses)
	}
	awaitDatagram(t, memberSock, "<alert-ind>false</alert-ind>")

	// Cancelling again finds nothing outstanding.
	responses = collectResponses(t, s, alertMessage("alert-3", "sip:test_group@example.test", "false"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 404") {
		t.Fatalf("re-cancel responses = %v, want 404", responses)
	}
}

// Unauthorised alerts get the clause 12.1.3.1 step 4 a 403 with the negated
// alert indication.
func TestEmergencyAlertUnauthorisedGets403(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, false, false)

	responses := collectResponses(t, s, alertMessage("alert-403", "sip:test_group@example.test", "true"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
	if !strings.Contains(responses[0], "<alert-ind>false</alert-ind>") {
		t.Fatalf("403 lacks the negated alert indication:\n%s", responses[0])
	}
}

// An alert on an unknown group is 404 with warning 163.
func TestEmergencyAlertUnknownGroup(t *testing.T) {
	s, st := groupCallFixture(t)
	allowEmergency(t, st, true, true)
	responses := collectResponses(t, s, alertMessage("alert-404", "sip:nope@example.test", "true"))
	if len(responses) != 1 || !strings.Contains(responses[0], `"163 the group identity indicated in the request does not exist"`) {
		t.Fatalf("responses = %v, want 404 with warning 163", responses)
	}
}

// awaitDatagram reads from sock until a datagram contains want, or the
// deadline expires.
//
// A test that never answers a notification MESSAGE will see it again:
// the server's non-INVITE client transaction retransmits on timer E
// (RFC 3261 clause 17.1.2.2) until it gets a response. So the datagram
// carrying the next thing a test is waiting for can arrive behind one or
// more retransmissions of the last one, which is a matter of timing
// rather than of correctness, and showed up as an intermittent failure
// on a loaded machine but not on an idle one.
func awaitDatagram(t *testing.T, sock net.PacketConn, want string) string {
	t.Helper()
	buf := make([]byte, 8192)
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		_ = sock.SetReadDeadline(deadline)
		n, _, err := sock.ReadFrom(buf)
		if err != nil {
			break
		}
		last = string(buf[:n])
		if strings.Contains(last, want) {
			return last
		}
	}
	if last == "" {
		t.Fatalf("nothing containing %q arrived", want)
	}
	t.Fatalf("no datagram contained %q; the last one was:\n%s", want, last)
	return ""
}

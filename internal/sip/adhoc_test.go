package sip

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

// adhocInvite builds a clause 17.2.2.1.1 originating INVITE: mcptt-info with
// <session-type>adhoc</session-type> (plus an optional adhoc identity in
// <mcptt-request-uri> and optional <call-participants-criterias>), an
// RFC 5366 resource-lists part naming the participants, and the SDP offer.
func adhocInvite(callID, requestURI, criteria string, participants []string) string {
	info := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`
	if requestURI != "" {
		info += `<mcptt-request-uri><mcpttURI>` + requestURI + `</mcpttURI></mcptt-request-uri>`
	}
	info += `<session-type>adhoc</session-type>`
	if criteria != "" {
		info += `<call-participants-criterias>` + criteria + `</call-participants-criterias>`
	}
	info += `</mcptt-Params></mcpttinfo>`

	lists := `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>`
	for _, p := range participants {
		lists += `<entry uri="` + p + `"/>`
	}
	lists += `</list></resource-lists>`

	sdp := "v=0\r\n" +
		"o=ue 1 1 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=application 49172 udp MCPTT\r\n" +
		"a=fmtp:MCPTT mc_implicit_request\r\n"

	body := "--adh\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + info +
		"\r\n--adh\r\nContent-Type: application/resource-lists+xml\r\n\r\n" + lists +
		"\r\n--adh\r\nContent-Type: application/sdp\r\n\r\n" + sdp +
		"\r\n--adh--\r\n"
	return "INVITE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:caller@198.51.100.116:5060>\r\n" +
		`Content-Type: multipart/mixed;boundary="adh"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

func adhocFixture(t *testing.T) (*Server, *sqlite.Store) {
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

	if _, err := st.CreateUser(context.Background(), store.User{
		IMPU: "sip:caller@example.test", MCPTTID: "sip:caller@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	return s, st
}

// addAdhocParticipant provisions a served, registered user whose contact is a
// live capture socket, with poc-settings published so the leg is allowed.
func addAdhocParticipant(t *testing.T, st *sqlite.Store, impu string) net.PacketConn {
	t.Helper()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, store.User{IMPU: impu, MCPTTID: impu, Enabled: true}); err != nil {
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
		PublicIdentity: impu, Registered: true,
		ContactURI: "sip:" + impu + "@127.0.0.1:" + portStr,
		SourceIP:   "127.0.0.1", SourcePort: port, Transport: "udp",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPublishedState(ctx, store.PublishedState{
		UserURI: impu,
		Event:   "poc-settings",
		Body:    `<poc-settings><entity id="p"><am-settings><answer-mode>automatic</answer-mode></am-settings></entity></poc-settings>`,
	}); err != nil {
		t.Fatal(err)
	}
	return sock
}

// An ad hoc INVITE with a participant list is accepted: 100/180/200, a
// generated adhoc group identity announced back in the 200's mcptt-info, and
// the participant's leg on the wire before the 200 (clause 17.4.2.2 steps 10,
// 15 and the 6.3.3.2.3.2 response shape).
func TestAdhocInviteAcceptedWithGeneratedIdentity(t *testing.T) {
	s, st := adhocFixture(t)
	sock := addAdhocParticipant(t, st, "sip:responder@example.test")

	var rx string
	var rxErr error
	var responses []string
	raw := adhocInvite("adhoc-ok-1", "", "", []string{"sip:responder@example.test"})
	s.handleRaw(context.Background(), "192.0.2.52:5060", "udp", []byte(raw), func(b []byte) error {
		responses = append(responses, string(b))
		if strings.HasPrefix(string(b), "SIP/2.0 200") && rx == "" {
			_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 8192)
			n, _, err := sock.ReadFrom(buf)
			if err != nil {
				rxErr = err
				return nil
			}
			rx = string(buf[:n])
		}
		return nil
	})

	if len(responses) != 3 {
		t.Fatalf("got %d responses, want 100/180/200:\n%s", len(responses), strings.Join(responses, "\n---\n"))
	}
	for i, want := range []string{"SIP/2.0 100 Trying", "SIP/2.0 180 Ringing", "SIP/2.0 200 OK"} {
		if !strings.HasPrefix(responses[i], want) {
			t.Fatalf("response %d = %q, want prefix %q", i, firstLine(responses[i]), want)
		}
	}
	if rxErr != nil {
		t.Fatalf("participant leg was not on the wire by the time the 200 was sent: %v", rxErr)
	}

	final := responses[2]
	for _, want := range []string{
		// Clause 6.3.3.2.3.2: session identity Contact with isfocus and tags.
		"Contact: <sip:mcptt-session-",
		";isfocus",
		"+g.3gpp.mcptt",
		"P-Asserted-Identity: <sip:mcptt-as@",
		"Session-Expires: 1800;refresher=uac\r\n",
		"Require: timer\r\n",
		// Step 10: no client-supplied identity, so the controlling function
		// generated one and announces it in the response's mcptt-info.
		"<mcpttURI>sip:mcptt-adhoc-",
		"<session-type>adhoc</session-type>",
	} {
		if !strings.Contains(final, want) {
			t.Fatalf("200 OK missing pinned element %q:\n%s", want, final)
		}
	}

	for _, want := range []string{
		"INVITE sip:responder@example.test SIP/2.0",
		// Clause 17.4.2.1.1: the participant's leg is classified adhoc and
		// carries the adhoc group identity.
		"<session-type>adhoc</session-type>",
		"<mcptt-calling-group-id><mcpttURI>sip:mcptt-adhoc-",
		"Answer-Mode: Auto\r\n",
	} {
		if !strings.Contains(rx, want) {
			t.Fatalf("participant INVITE missing pinned element %q:\n%s", want, rx)
		}
	}
}

// A client-supplied adhoc identity is used as-is instead of generating one.
func TestAdhocInviteKeepsClientSuppliedIdentity(t *testing.T) {
	s, st := adhocFixture(t)
	addAdhocParticipant(t, st, "sip:responder@example.test")

	responses := collectResponses(t, s,
		adhocInvite("adhoc-ok-2", "sip:incident-77@example.test", "", []string{"sip:responder@example.test"}))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}
	if !strings.Contains(responses[2], "<mcpttURI>sip:incident-77@example.test</mcpttURI>") {
		t.Fatalf("200 does not announce the client-supplied adhoc identity:\n%s", responses[2])
	}
	if strings.Contains(responses[2], "sip:mcptt-adhoc-") {
		t.Fatalf("a generated identity was used despite the client supplying one:\n%s", responses[2])
	}
}

// Clause 17.4.2.2 step 5: ad hoc support disabled means 403 with warning "186".
func TestAdhocInviteDisabledGets403With186(t *testing.T) {
	s, _ := adhocFixture(t)
	s.cfg.SIP.Adhoc.Enabled = false

	responses := collectResponses(t, s,
		adhocInvite("adhoc-186", "", "", []string{"sip:responder@example.test"}))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
	if !strings.Contains(responses[0], `"186 the MCPTT system do not support adhoc group call"`) {
		t.Fatalf("403 lacks warning 186:\n%s", responses[0])
	}
}

// Clause 17.4.2.2 step 7: a participant list and criteria together, or
// neither, mean the participants cannot be determined - 403 with "187".
func TestAdhocInviteUndeterminableParticipantsGets403With187(t *testing.T) {
	s, _ := adhocFixture(t)

	for name, raw := range map[string]string{
		"list and criteria": adhocInvite("adhoc-187a", "", "<crit/>", []string{"sip:responder@example.test"}),
		"neither":           adhocInvite("adhoc-187b", "", "", nil),
	} {
		responses := collectResponses(t, s, raw)
		if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
			t.Fatalf("%s: responses = %v, want exactly one 403", name, responses)
		}
		if !strings.Contains(responses[0], `"187 can't determine the adhoc group participants"`) {
			t.Fatalf("%s: 403 lacks warning 187:\n%s", name, responses[0])
		}
	}
}

// Clause 17.4.2.2 step 6: more participants than the configured maximum is
// refused with warning "189".
func TestAdhocInviteOverParticipantLimitGets403With189(t *testing.T) {
	s, _ := adhocFixture(t)
	s.cfg.SIP.Adhoc.MaxParticipants = 2

	responses := collectResponses(t, s, adhocInvite("adhoc-189", "", "", []string{
		"sip:a@example.test", "sip:b@example.test", "sip:c@example.test",
	}))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
	if !strings.Contains(responses[0], `"189 maximum number of allowed adhoc group participants exceeded"`) {
		t.Fatalf("403 lacks warning 189:\n%s", responses[0])
	}
}

// The served-user check of clause 10.1.1.3.1.1 applies to ad hoc originations.
func TestAdhocInviteFromUnknownUserGets404With141(t *testing.T) {
	s, _ := adhocFixture(t)

	raw := strings.Replace(
		adhocInvite("adhoc-141", "", "", []string{"sip:responder@example.test"}),
		"From: <sip:caller@example.test>;tag=from1",
		"From: <sip:stranger@example.test>;tag=from1", 1)
	responses := collectResponses(t, s, raw)
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 404") {
		t.Fatalf("responses = %v, want exactly one 404", responses)
	}
	if !strings.Contains(responses[0], `"141 user unknown to the participating function"`) {
		t.Fatalf("404 lacks warning 141:\n%s", responses[0])
	}
}

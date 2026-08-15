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

// privateInvite builds a clause 11.1.1.2.1 originating INVITE: mcptt-info
// with <session-type>private</session-type> and the callee in an RFC 5366
// resource-lists part.
func privateInvite(callID string, callees []string) string {
	info := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		`<session-type>private</session-type>` +
		`</mcptt-Params></mcpttinfo>`
	lists := `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>`
	for _, callee := range callees {
		lists += `<entry uri="` + callee + `"/>`
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
	body := "--pvt\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + info +
		"\r\n--pvt\r\nContent-Type: application/resource-lists+xml\r\n\r\n" + lists +
		"\r\n--pvt\r\nContent-Type: application/sdp\r\n\r\n" + sdp +
		"\r\n--pvt--\r\n"
	return "INVITE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:caller@198.51.100.116:5060>\r\n" +
		`Content-Type: multipart/mixed;boundary="pvt"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

func privateFixture(t *testing.T) (*Server, *sqlite.Store) {
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

// The callee answers: the caller's 200 follows the callee's 200 (clause
// 11.1.1.4.2), and the callee's leg carries session-type private with the
// callee in mcptt-request-uri and no calling group (clause 11.1.1.4.1).
func TestPrivateCallInvitesCalleeAndAnswersAfterCalleeAnswer(t *testing.T) {
	s, st := privateFixture(t)
	ctx := context.Background()

	if _, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:callee@example.test", MCPTTID: "sip:callee@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPublishedState(ctx, store.PublishedState{
		UserURI: "sip:callee@example.test",
		Event:   "poc-settings",
		Body:    `<poc-settings><entity id="c"><am-settings><answer-mode>automatic</answer-mode></am-settings></entity></poc-settings>`,
	}); err != nil {
		t.Fatal(err)
	}

	// The callee is a real UDP socket that answers the leg with a 200.
	calleeSock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = calleeSock.Close() })
	_, portStr, _ := net.SplitHostPort(calleeSock.LocalAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: "sip:callee@example.test", Registered: true,
		ContactURI: "sip:callee@127.0.0.1:" + portStr,
		SourceIP:   "127.0.0.1", SourcePort: port, Transport: "udp",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	var calleeInvite string
	go func() {
		buf := make([]byte, 8192)
		_ = calleeSock.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := calleeSock.ReadFrom(buf)
		if err != nil {
			return
		}
		calleeInvite = string(buf[:n])
		// Minimal 200 OK with an SDP answer, echoing the dialog identifiers.
		via := headerLine(calleeInvite, "Via")
		fromH := headerLine(calleeInvite, "From")
		toH := headerLine(calleeInvite, "To") + ";tag=callee1"
		callIDH := headerLine(calleeInvite, "Call-ID")
		cseq := headerLine(calleeInvite, "CSeq")
		sdp := "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
			"m=audio 40010 RTP/AVP 0\r\n"
		resp := "SIP/2.0 200 OK\r\n" +
			"Via: " + via + "\r\n" +
			"From: " + fromH + "\r\n" +
			"To: " + toH + "\r\n" +
			"Call-ID: " + callIDH + "\r\n" +
			"CSeq: " + cseq + "\r\n" +
			"Contact: <sip:callee@127.0.0.1:" + portStr + ">\r\n" +
			"Content-Type: application/sdp\r\n" +
			"Content-Length: " + fmt.Sprint(len(sdp)) + "\r\n\r\n" + sdp
		_ = from
		// The response is injected through the server's own ingress path, as
		// the production listener would deliver it.
		s.handleRaw(context.Background(), "127.0.0.1:"+portStr, "udp", []byte(resp), func([]byte) error { return nil })
	}()

	responses := collectResponses(t, s, privateInvite("pvt-ok-1", []string{"sip:callee@example.test"}))
	if len(responses) != 3 {
		t.Fatalf("got %d responses, want 100/180/200:\n%s", len(responses), strings.Join(responses, "\n---\n"))
	}
	for i, want := range []string{"SIP/2.0 100 Trying", "SIP/2.0 180 Ringing", "SIP/2.0 200 OK"} {
		if !strings.HasPrefix(responses[i], want) {
			t.Fatalf("response %d = %q, want prefix %q", i, firstLine(responses[i]), want)
		}
	}
	final := responses[2]
	for _, want := range []string{
		"Contact: <sip:mcptt-session-",
		";isfocus",
		"Session-Expires: 1800;refresher=uac\r\n",
		"Content-Type: application/sdp",
	} {
		if !strings.Contains(final, want) {
			t.Fatalf("200 OK missing %q:\n%s", want, final)
		}
	}
	for _, want := range []string{
		"INVITE sip:callee@example.test SIP/2.0",
		"<session-type>private</session-type>",
		"<mcptt-request-uri><mcpttURI>sip:callee@example.test</mcpttURI></mcptt-request-uri>",
		"Answer-Mode: Auto\r\n",
	} {
		if !strings.Contains(calleeInvite, want) {
			t.Fatalf("callee INVITE missing %q:\n%s", want, calleeInvite)
		}
	}
	if strings.Contains(calleeInvite, "mcptt-calling-group-id") {
		t.Fatalf("private leg must not carry a calling group id:\n%s", calleeInvite)
	}
}

// Clause 11.1.1.4.2 steps 3/4: no callee, or more than one, is 403 "145".
func TestPrivateCallWithoutSingleCalleeGets403With145(t *testing.T) {
	s, _ := privateFixture(t)
	for name, callees := range map[string][]string{
		"none": nil,
		"two":  {"sip:a@example.test", "sip:b@example.test"},
	} {
		responses := collectResponses(t, s, privateInvite("pvt-145-"+name, callees))
		if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
			t.Fatalf("%s: responses = %v, want exactly one 403", name, responses)
		}
		if !strings.Contains(responses[0], `"145 unable to determine called party"`) {
			t.Fatalf("%s: 403 lacks warning 145:\n%s", name, responses[0])
		}
	}
}

// Clause 11.1.1.3.2 step 7: an unbound callee is a 404.
func TestPrivateCallToUnknownCalleeGets404(t *testing.T) {
	s, _ := privateFixture(t)
	responses := collectResponses(t, s, privateInvite("pvt-404", []string{"sip:nobody@example.test"}))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 404") {
		t.Fatalf("responses = %v, want exactly one 404", responses)
	}
}

// Clause 11.1.1.3.2 step 7a: a callee without poc-settings is 480 "146".
func TestPrivateCallWithoutCalleeSettingsGets480With146(t *testing.T) {
	s, st := privateFixture(t)
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:callee@example.test", MCPTTID: "sip:callee@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: "sip:callee@example.test", Registered: true,
		ContactURI: "sip:callee@127.0.0.1:5299",
		SourceIP:   "127.0.0.1", SourcePort: 5299, Transport: "udp",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	responses := collectResponses(t, s, privateInvite("pvt-146", []string{"sip:callee@example.test"}))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 480") {
		t.Fatalf("responses = %v, want exactly one 480", responses)
	}
	if !strings.Contains(responses[0], `"146 T-PF unable to determine the service settings for the called user"`) {
		t.Fatalf("480 lacks warning 146:\n%s", responses[0])
	}
}

// headerLine returns the value of the first occurrence of a header in a raw
// SIP message.
func headerLine(raw, name string) string {
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)+":") {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

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

// sdsMessage builds a TS 24.282 clause 9.2.2 standalone SDS SIP MESSAGE with
// the three MCData MIME bodies.
func sdsMessage(callID, requestType, requestURI string, targets []string) string {
	info := `<mcdatainfo xmlns="urn:3gpp:ns:mcdataInfo:1.0"><mcdata-Params>` +
		`<request-type>` + requestType + `</request-type>`
	if requestURI != "" {
		info += `<mcdata-request-uri><mcdataURI>` + requestURI + `</mcdataURI></mcdata-request-uri>`
	}
	info += `</mcdata-Params></mcdatainfo>`
	lists := `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>`
	for _, tgt := range targets {
		lists += `<entry uri="` + tgt + `"/>`
	}
	lists += `</list></resource-lists>`
	signalling := "SDS-SIGNALLING"
	payload := "hello over sds"
	body := "--sds\r\nContent-Type: application/vnd.3gpp.mcdata-info+xml\r\n\r\n" + info +
		"\r\n--sds\r\nContent-Type: application/vnd.3gpp.mcdata-signalling\r\n\r\n" + signalling +
		"\r\n--sds\r\nContent-Type: application/vnd.3gpp.mcdata-payload\r\n\r\n" + payload
	if len(targets) > 0 {
		body += "\r\n--sds\r\nContent-Type: application/resource-lists+xml\r\n\r\n" + lists
	}
	body += "\r\n--sds--\r\n"
	return "MESSAGE sip:mcdata-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcdata-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		`Content-Type: multipart/mixed;boundary="sds"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

// registerAtSocket binds a user to a live capture socket.
func registerAtSocket(t *testing.T, st interface {
	UpsertRegistration(context.Context, store.Registration) (store.Registration, error)
}, impu string) net.PacketConn {
	t.Helper()
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	_, portStr, _ := net.SplitHostPort(sock.LocalAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if _, err := st.UpsertRegistration(context.Background(), store.Registration{
		PublicIdentity: impu, Registered: true,
		ContactURI: "sip:" + impu + "@127.0.0.1:" + portStr,
		SourceIP:   "127.0.0.1", SourcePort: port, Transport: "udp",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return sock
}

// One-to-one SDS is forwarded to the target with the clause 9.2.2.4.1.1
// shape and answered 202 toward the originator.
func TestOneToOneSDSForwardedAndAccepted(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:peer@example.test", MCPTTID: "sip:peer@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	sock := registerAtSocket(t, st, "sip:peer@example.test")

	responses := collectResponses(t, s, sdsMessage("sds-1", "one-to-one-sds", "", []string{"sip:peer@example.test"}))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 202") {
		t.Fatalf("responses = %v, want exactly one 202", responses)
	}

	_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, _, err := sock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("forwarded MESSAGE never arrived: %v", err)
	}
	fwd := string(buf[:n])
	for _, want := range []string{
		"MESSAGE sip:peer@example.test SIP/2.0",
		"Accept-Contact: *;+g.3gpp.mcdata.sds;require;explicit",
		`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.sds"`,
		"P-Asserted-Service: urn:urn-7:3gpp-service.ims.icsi.mcdata.sds",
		"Content-Type: application/vnd.3gpp.mcdata-signalling",
		"SDS-SIGNALLING",
		"hello over sds",
		"<mcdata-request-uri><mcdataURI>sip:peer@example.test</mcdataURI></mcdata-request-uri>",
	} {
		if !strings.Contains(fwd, want) {
			t.Fatalf("forwarded MESSAGE missing %q:\n%s", want, fwd)
		}
	}
}

// Group SDS goes to the affiliated members and carries the calling group id.
func TestGroupSDSForwardedToAffiliatedMembers(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()

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
	sock := registerAtSocket(t, st, "sip:member2@example.test")

	responses := collectResponses(t, s, sdsMessage("sds-g1", "group-sds", "sip:test_group@example.test", nil))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 202") {
		t.Fatalf("responses = %v, want exactly one 202", responses)
	}

	_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, _, err := sock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("group SDS never reached the member: %v", err)
	}
	fwd := string(buf[:n])
	if !strings.Contains(fwd, "<mcdata-calling-group-id><mcdataURI>sip:test_group@example.test</mcdataURI></mcdata-calling-group-id>") {
		t.Fatalf("forwarded group SDS lacks the calling group id:\n%s", fwd)
	}
}

// Clause 9.2.2.4.2 step 2: a missing MCData MIME body is 403 with "199".
func TestSDSMissingBodiesGets403With199(t *testing.T) {
	s, _ := groupCallFixture(t)
	raw := sdsMessage("sds-199", "one-to-one-sds", "", []string{"sip:peer@example.test"})
	raw = strings.Replace(raw, "application/vnd.3gpp.mcdata-signalling", "application/vnd.3gpp.other", 1)
	// Fix the Content-Length after mutation of equal length? Lengths are
	// equal ("mcdata-signalling" vs "other" differ) - rebuild instead.
	info := `<mcdatainfo xmlns="urn:3gpp:ns:mcdataInfo:1.0"><mcdata-Params><request-type>one-to-one-sds</request-type></mcdata-Params></mcdatainfo>`
	body := "--sds\r\nContent-Type: application/vnd.3gpp.mcdata-info+xml\r\n\r\n" + info + "\r\n--sds--\r\n"
	raw = "MESSAGE sip:mcdata-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKsds199\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcdata-as@example.test>\r\n" +
		"Call-ID: sds-199\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		`Content-Type: multipart/mixed;boundary="sds"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
	responses := collectResponses(t, s, raw)
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
	if !strings.Contains(responses[0], `"199 expected MIME bodies not in the request"`) {
		t.Fatalf("403 lacks warning 199:\n%s", responses[0])
	}
}

// A non-member group SDS is refused with warning "116"; an unaffiliated
// member with "120"; an unknown group with "163".
func TestGroupSDSRejections(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()

	responses := collectResponses(t, s, sdsMessage("sds-163", "group-sds", "sip:no-such-group@example.test", nil))
	if len(responses) != 1 || !strings.Contains(responses[0], `"163 the group identity indicated in the request does not exist"`) {
		t.Fatalf("unknown group: %v", responses)
	}

	if _, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:outsider@example.test", MCPTTID: "sip:outsider@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	raw := strings.ReplaceAll(sdsMessage("sds-116", "group-sds", "sip:test_group@example.test", nil),
		"sip:caller@example.test", "sip:outsider@example.test")
	responses = collectResponses(t, s, raw)
	if len(responses) != 1 || !strings.Contains(responses[0], `"116 user is not part of the MCData group"`) {
		t.Fatalf("non-member: %v", responses)
	}
}

// A plain MESSAGE without MCData bodies is now 200, not 405 (MESSAGE is
// advertised in Allow).
func TestPlainMessageAccepted(t *testing.T) {
	s, _ := groupCallFixture(t)
	raw := "MESSAGE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKplainmsg\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: plain-msg-1\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 5\r\n\r\nhello"
	responses := collectResponses(t, s, raw)
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want exactly one 200", responses)
	}
}

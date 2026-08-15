package sip

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// buildSDSSignalling builds a clause 15.1.2.1 SDS SIGNALLING PAYLOAD head:
// type(1) + date-and-time(5) + conversation(16) + message(16).
func buildSDSSignalling(conversation, message []byte) []byte {
	out := []byte{mcdataSDSSignallingPayload, 0, 0, 0, 0, 0}
	out = append(out, conversation...)
	out = append(out, message...)
	return out
}

// buildSDSNotification builds a clause 15.1.5.1 SDS NOTIFICATION head:
// type(1) + notification-type(1) + date-and-time(5) + conversation(16) +
// message(16).
func buildSDSNotification(disposition byte, conversation, message []byte) []byte {
	out := []byte{mcdataSDSNotification, disposition, 0, 0, 0, 0, 0}
	out = append(out, conversation...)
	out = append(out, message...)
	return out
}

func testIDs() ([]byte, []byte) {
	conversation := make([]byte, 16)
	message := make([]byte, 16)
	for i := range conversation {
		conversation[i] = byte(i + 1)
		message[i] = byte(0xf0 - i)
	}
	return conversation, message
}

// sdsWithSignalling builds a one-to-one SDS carrying the given clause 15
// signalling body.
func sdsWithSignalling(callID string, signalling []byte) string {
	info := `<mcdatainfo xmlns="urn:3gpp:ns:mcdataInfo:1.0"><mcdata-Params>` +
		`<request-type>one-to-one-sds</request-type></mcdata-Params></mcdatainfo>`
	lists := `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>` +
		`<entry uri="sip:peer@example.test"/></list></resource-lists>`
	body := "--sds\r\nContent-Type: application/vnd.3gpp.mcdata-info+xml\r\n\r\n" + info +
		"\r\n--sds\r\nContent-Type: application/vnd.3gpp.mcdata-signalling\r\n\r\n" + string(signalling) +
		"\r\n--sds\r\nContent-Type: application/vnd.3gpp.mcdata-payload\r\n\r\nhello" +
		"\r\n--sds\r\nContent-Type: application/resource-lists+xml\r\n\r\n" + lists +
		"\r\n--sds--\r\n"
	return "MESSAGE sip:mcdata-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"From: <sip:caller@example.test>;tag=c1\r\n" +
		"To: <sip:mcdata-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		`Content-Type: multipart/mixed;boundary="sds"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

// dispositionMessage builds a disposition notification (signalling, no
// payload) naming the original sender.
func dispositionMessage(callID string, signalling []byte) string {
	info := `<mcdatainfo xmlns="urn:3gpp:ns:mcdataInfo:1.0"><mcdata-Params></mcdata-Params></mcdatainfo>`
	lists := `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>` +
		`<entry uri="sip:caller@example.test"/></list></resource-lists>`
	body := "--d\r\nContent-Type: application/vnd.3gpp.mcdata-info+xml\r\n\r\n" + info +
		"\r\n--d\r\nContent-Type: application/vnd.3gpp.mcdata-signalling\r\n\r\n" + string(signalling) +
		"\r\n--d\r\nContent-Type: application/resource-lists+xml\r\n\r\n" + lists +
		"\r\n--d--\r\n"
	return "MESSAGE sip:mcdata-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"From: <sip:peer@example.test>;tag=p1\r\n" +
		"To: <sip:mcdata-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		`Content-Type: multipart/mixed;boundary="d"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

// readDatagram reads one datagram with a short deadline.
func readDatagram(sock net.PacketConn) (string, error) {
	buf := make([]byte, 8192)
	_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := sock.ReadFrom(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// The clause 15 head decodes with the spare bits of the message type octet
// masked off (table 15.2.2-1).
func TestParseMcdataSignalling(t *testing.T) {
	conversation, message := testIDs()

	sig, ok := parseMcdataSignalling(buildSDSSignalling(conversation, message))
	if !ok || sig.MessageType != mcdataSDSSignallingPayload {
		t.Fatalf("signalling parse: ok=%v type=%d", ok, sig.MessageType)
	}
	if sig.ConversationID != hex.EncodeToString(conversation) || sig.MessageID != hex.EncodeToString(message) {
		t.Fatalf("ids = %s / %s", sig.ConversationID, sig.MessageID)
	}

	// Spare bits 7-8 set must not change the identity.
	spare := buildSDSSignalling(conversation, message)
	spare[0] |= 0xc0
	if sig2, ok := parseMcdataSignalling(spare); !ok || sig2.MessageType != mcdataSDSSignallingPayload {
		t.Fatalf("spare bits changed the message type: ok=%v type=%d", ok, sig2.MessageType)
	}

	notif, ok := parseMcdataSignalling(buildSDSNotification(mcdataDispositionRead, conversation, message))
	if !ok || notif.NotificationType != mcdataDispositionRead {
		t.Fatalf("notification parse: ok=%v disposition=%d", ok, notif.NotificationType)
	}
	if notif.correlationKey() != sig.correlationKey() {
		t.Fatalf("notification does not correlate to its payload:\n%s\n%s",
			notif.correlationKey(), sig.correlationKey())
	}

	// Truncated and unknown messages are ignored (clause 15.1's rule).
	if _, ok := parseMcdataSignalling([]byte{mcdataSDSSignallingPayload, 1, 2}); ok {
		t.Fatal("truncated message should not parse")
	}
	if _, ok := parseMcdataSignalling([]byte{0x3f}); ok {
		t.Fatal("unknown message type should not parse")
	}
}

// A disposition whose Conversation/Message ID matches a remembered SDS is
// forwarded; one that matches nothing is refused with warning 216
// (clause 12.2.3 steps 4-5).
func TestDispositionCorrelation(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()
	conversation, message := testIDs()

	if _, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:peer@example.test", MCPTTID: "sip:peer@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	_ = registerAtSocket(t, st, "sip:peer@example.test")
	origSock := registerAtSocket(t, st, "sip:caller@example.test")

	// Uncorrelated disposition first: refused with warning 216.
	responses := collectResponses(t, s,
		dispositionMessage("disp-uncorr", buildSDSNotification(mcdataDispositionDelivered, conversation, message)))
	if len(responses) != 1 || !strings.Contains(responses[0], `"216 unable to correlate the disposition notification"`) {
		t.Fatalf("uncorrelated disposition = %v, want 403 with warning 216", responses)
	}

	// Send the SDS so the transmission is remembered.
	responses = collectResponses(t, s, sdsWithSignalling("sds-corr", buildSDSSignalling(conversation, message)))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 202") {
		t.Fatalf("SDS = %v, want 202", responses)
	}

	// Now the disposition correlates and reaches the originator.
	responses = collectResponses(t, s,
		dispositionMessage("disp-corr", buildSDSNotification(mcdataDispositionRead, conversation, message)))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("correlated disposition = %v, want 200", responses)
	}
	if _, err := readDatagram(origSock); err != nil {
		t.Fatalf("originator never received the correlated disposition: %v", err)
	}
}

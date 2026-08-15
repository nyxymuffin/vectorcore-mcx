package sip

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// conferenceSubscribe builds a clause 10.1.3.2 SUBSCRIBE from a participant.
func conferenceSubscribe(callID, subscriber, groupURI, expires string) string {
	info := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		`<mcptt-request-uri><mcpttURI>` + groupURI + `</mcpttURI></mcptt-request-uri>` +
		`</mcptt-Params></mcpttinfo>`
	return "SUBSCRIBE sip:mcptt-session-x@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"From: <" + subscriber + ">;tag=cs1\r\n" +
		"To: <sip:mcptt-session-x@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 SUBSCRIBE\r\n" +
		"Event: conference\r\n" +
		"Accept: application/conference-info+xml\r\n" +
		"Expires: " + expires + "\r\n" +
		"Contact: <" + subscriber + ">\r\n" +
		"Content-Type: application/vnd.3gpp.mcptt-info+xml\r\n" +
		"Content-Length: " + fmt.Sprint(len(info)) + "\r\n\r\n" + info
}

// A participant's conference SUBSCRIBE gets 200 plus a NOTIFY whose
// conference-info lists the session participants (clauses 10.1.3.4.1,
// 6.3.3.4); a participant-set change re-notifies.
func TestConferenceSubscriptionAndChangeNotify(t *testing.T) {
	s, _ := groupCallFixture(t)

	var mu sync.Mutex
	var sent []string
	s.clientTxSendOverride = func(transport, target string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, string(packet))
		return nil
	}

	// An active group call makes the caller a participant.
	responses := collectResponses(t, s, snapshotGroupInvite("conf-call-1"))
	if len(responses) != 3 {
		t.Fatalf("call setup: %v", responses)
	}

	responses = collectResponses(t, s,
		conferenceSubscribe("conf-sub-1", "sip:caller@example.test", "sip:test_group@example.test", "4294967295"))
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("SUBSCRIBE responses = %v, want 200", responses)
	}

	// The initial NOTIFY carries the participant list.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		var notify string
		for _, m := range sent {
			if strings.HasPrefix(m, "NOTIFY ") && strings.Contains(m, "Event: conference") {
				notify = m
			}
		}
		mu.Unlock()
		if notify != "" {
			for _, want := range []string{
				"application/conference-info+xml",
				`entity="sip:test_group@example.test"`,
				`<user entity="sip:caller@example.test">`,
				"<status>connected</status>",
				"<mcptt-calling-group-id><mcpttURI>sip:test_group@example.test</mcpttURI></mcptt-calling-group-id>",
			} {
				if !strings.Contains(notify, want) {
					t.Fatalf("conference NOTIFY missing %q:\n%s", want, notify)
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no conference NOTIFY sent")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A participant-set change (BYE ends the call) re-notifies.
	mu.Lock()
	baseline := len(sent)
	mu.Unlock()
	bye := "BYE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKconfbye\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:test_group@example.test>;tag=x\r\n" +
		"Call-ID: conf-call-1\r\n" +
		"CSeq: 2 BYE\r\n" +
		"Content-Length: 0\r\n\r\n"
	collectResponses(t, s, bye)

	deadline = time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		change := false
		for _, m := range sent[baseline:] {
			if strings.HasPrefix(m, "NOTIFY ") && strings.Contains(m, "Event: conference") {
				change = true
			}
		}
		mu.Unlock()
		if change {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no change NOTIFY after the participant set shrank")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A non-participant is refused (clause 10.1.3.4.1 condition 1 a i).
func TestConferenceSubscriptionNonParticipantRefused(t *testing.T) {
	s, st := groupCallFixture(t)
	if _, err := st.CreateUser(context.Background(), store.User{
		IMPU: "sip:outsider@example.test", MCPTTID: "sip:outsider@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	collectResponses(t, s, snapshotGroupInvite("conf-call-2"))
	responses := collectResponses(t, s,
		conferenceSubscribe("conf-sub-2", "sip:outsider@example.test", "sip:test_group@example.test", "4294967295"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
}

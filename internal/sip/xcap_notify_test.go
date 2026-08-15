package sip

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// A change to a document whose AUID an xcap-diff subscriber watches produces
// an in-dialog change NOTIFY (RFC 5875) with an advancing CSeq.
func TestXCAPChangeTriggersNotify(t *testing.T) {
	s, _ := groupCallFixture(t)

	var mu sync.Mutex
	var sent []string
	s.clientTxSendOverride = func(transport, target string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, string(packet))
		return nil
	}

	subscribe := "SUBSCRIBE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKxsub1\r\n" +
		"From: <sip:caller@example.test>;tag=xs1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: xcap-sub-1\r\n" +
		"CSeq: 1 SUBSCRIBE\r\n" +
		"Event: xcap-diff; diff-processing=no-patching\r\n" +
		"Expires: 3600\r\n" +
		"Contact: <sip:caller@192.0.2.52:5060>\r\n" +
		"Content-Length: 0\r\n\r\n"
	responses := collectResponses(t, s, subscribe)
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("SUBSCRIBE responses = %v, want 200", responses)
	}

	mu.Lock()
	baseline := len(sent)
	mu.Unlock()

	s.NotifyXCAPChange("/org.openmobilealliance.groups/global/byGroupID/sip:test_group@example.test")

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		var notify string
		for _, m := range sent[baseline:] {
			if strings.HasPrefix(m, "NOTIFY ") {
				notify = m
			}
		}
		mu.Unlock()
		if notify != "" {
			for _, want := range []string{
				"Event: xcap-diff",
				"Call-ID: xcap-sub-1",
				"Subscription-State: active",
			} {
				if !strings.Contains(notify, want) {
					t.Fatalf("change NOTIFY missing %q:\n%s", want, notify)
				}
			}
			if !strings.Contains(notify, "CSeq: 2 NOTIFY") {
				t.Fatalf("change NOTIFY CSeq did not advance past the initial NOTIFY:\n%s", notify)
			}
			return
		}
		if time.Now().After(deadline) {
			mu.Lock()
			t.Fatalf("no change NOTIFY sent; %d messages after baseline", len(sent)-baseline)
			mu.Unlock()
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An unsubscribe (Expires 0) deregisters; changes no longer notify.
func TestXCAPUnsubscribeStopsChangeNotify(t *testing.T) {
	s, _ := groupCallFixture(t)
	subscribeTemplate := func(callID, expires string) string {
		return "SUBSCRIBE sip:mcptt-as@example.test SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKx" + callID + expires + "\r\n" +
			"From: <sip:caller@example.test>;tag=xs2\r\n" +
			"To: <sip:mcptt-as@example.test>\r\n" +
			"Call-ID: " + callID + "\r\n" +
			"CSeq: 1 SUBSCRIBE\r\n" +
			"Event: xcap-diff\r\n" +
			"Expires: " + expires + "\r\n" +
			"Contact: <sip:caller@192.0.2.52:5060>\r\n" +
			"Content-Length: 0\r\n\r\n"
	}
	collectResponses(t, s, subscribeTemplate("xcap-sub-2", "3600"))
	collectResponses(t, s, subscribeTemplate("xcap-sub-2", "0"))

	var mu sync.Mutex
	count := 0
	s.clientTxSendOverride = func(transport, target string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasPrefix(string(packet), "NOTIFY ") {
			count++
		}
		return nil
	}
	s.NotifyXCAPChange("/org.openmobilealliance.groups/global/byGroupID/sip:test_group@example.test")
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if count != 0 {
		t.Fatalf("unsubscribed watcher still got %d NOTIFYs", count)
	}
}

var _ = fmt.Sprint // keep fmt while the file grows

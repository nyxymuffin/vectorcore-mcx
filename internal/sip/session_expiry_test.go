package sip

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// RFC 4028 supervision: an answered call whose session expires without a
// refresh is reaped - the caller gets an in-dialog BYE and the call record
// terminates.
func TestExpiredSessionIsReapedWithCallerBYE(t *testing.T) {
	s, st := groupCallFixture(t)
	s.sessionExpiryOverride = 50 * time.Millisecond
	ctx := context.Background()

	responses := collectResponses(t, s, snapshotGroupInvite("exp-1"))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}
	if !strings.Contains(responses[2], "Session-Expires: 1800;refresher=uac\r\n") {
		t.Fatalf("200 lacks Session-Expires:\n%s", responses[2])
	}
	call, err := st.GetCall(ctx, "exp-1")
	if err != nil || call == nil {
		t.Fatalf("call not stored: %v", err)
	}
	if call.SessionExpiresAt.IsZero() {
		t.Fatal("session expiration was not stamped at answer")
	}

	time.Sleep(80 * time.Millisecond)
	s.reapExpiredSessions(ctx)

	call, err = st.GetCall(ctx, "exp-1")
	if err != nil || call == nil {
		t.Fatal(err)
	}
	if call.State != "terminated" {
		t.Fatalf("state = %q, want terminated after expiry", call.State)
	}
}

// A session refresh (in-dialog UPDATE) extends the expiration and the reaper
// leaves the call alone.
func TestSessionRefreshExtendsExpiry(t *testing.T) {
	s, st := groupCallFixture(t)
	s.sessionExpiryOverride = 150 * time.Millisecond
	ctx := context.Background()

	responses := collectResponses(t, s, snapshotGroupInvite("exp-2"))
	if len(responses) != 3 {
		t.Fatalf("responses = %v", responses)
	}
	toTag := tagFromResponse(responses[2])
	before, _ := st.GetCall(ctx, "exp-2")

	time.Sleep(60 * time.Millisecond)
	update := "UPDATE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKupd2\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:test_group@example.test>;tag=" + toTag + "\r\n" +
		"Call-ID: exp-2\r\n" +
		"CSeq: 2 UPDATE\r\n" +
		"Session-Expires: 1800\r\n" +
		"Content-Length: 0\r\n\r\n"
	upd := collectResponses(t, s, update)
	if len(upd) != 1 || !strings.HasPrefix(upd[0], "SIP/2.0 200") {
		t.Fatalf("UPDATE responses = %v, want 200", upd)
	}
	if !strings.Contains(upd[0], "Session-Expires: 1800;refresher=uac\r\n") {
		t.Fatalf("refresh 200 lacks Session-Expires (RFC 4028 UAS behavior):\n%s", upd[0])
	}

	after, _ := st.GetCall(ctx, "exp-2")
	if before == nil || after == nil || !after.SessionExpiresAt.After(before.SessionExpiresAt) {
		t.Fatalf("refresh did not extend expiry: before=%v after=%v",
			before.SessionExpiresAt, after.SessionExpiresAt)
	}

	// Within the refreshed window the reaper must not touch the call.
	s.reapExpiredSessions(ctx)
	call, _ := st.GetCall(ctx, "exp-2")
	if call.State == "terminated" {
		t.Fatal("refreshed session was reaped early")
	}
}

// The reaped BYE toward the caller carries the dialog identity (local tag on
// From, caller's tag on To) and goes to the caller's source address.
func TestCallerBYECarriesDialogIdentity(t *testing.T) {
	s, st := groupCallFixture(t)
	s.sessionExpiryOverride = 10 * time.Millisecond
	ctx := context.Background()

	responses := collectResponses(t, s, snapshotGroupInvite("exp-3"))
	if len(responses) != 3 {
		t.Fatalf("responses = %v", responses)
	}
	toTag := tagFromResponse(responses[2])

	// Capture what sendTransacted puts on the wire by intercepting the
	// client transaction send function. The retransmission goroutine keeps
	// calling it, so the capture is mutex-guarded.
	var mu sync.Mutex
	var sent []string
	s.clientTxSendOverride = func(transport, target string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, fmt.Sprintf("%s|%s|%s", transport, target, packet))
		return nil
	}

	time.Sleep(30 * time.Millisecond)
	s.reapExpiredSessions(ctx)

	call, _ := st.GetCall(ctx, "exp-3")
	if call.State != "terminated" {
		t.Fatalf("state = %q, want terminated", call.State)
	}
	mu.Lock()
	joined := strings.Join(sent, "\n===\n")
	mu.Unlock()
	for _, want := range []string{
		// Request-URI and target from the caller's Contact (RFC 3261 §12.2).
		"BYE sip:caller@198.51.100.116:5060",
		"|198.51.100.116:5060|",
		"To: <sip:caller@example.test>;tag=from1",
		";tag=" + toTag,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("caller BYE missing %q:\n%s", want, joined)
		}
	}
}

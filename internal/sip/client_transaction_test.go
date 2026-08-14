package sip

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
)

// countingSender records every wire write.
type countingSender struct {
	mu     sync.Mutex
	writes [][]byte
}

func (c *countingSender) send(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	return nil
}

func (c *countingSender) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func (c *countingSender) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) == 0 {
		return ""
	}
	return string(c.writes[len(c.writes)-1])
}

func txRequest(method, branch string) []byte {
	return []byte(method + " sip:member@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=" + branch + "\r\n" +
		"From: <sip:mcptt-as@example.test>;tag=as1\r\n" +
		"To: <sip:member@example.test>\r\n" +
		"Call-ID: ctx-" + branch + "\r\n" +
		"CSeq: 1 " + method + "\r\n" +
		"Content-Length: 0\r\n\r\n")
}

func txResponse(t *testing.T, status, branch, method string) *Message {
	t.Helper()
	msg, err := Parse([]byte("SIP/2.0 " + status + "\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=" + branch + "\r\n" +
		"From: <sip:mcptt-as@example.test>;tag=as1\r\n" +
		"To: <sip:member@example.test>;tag=member1\r\n" +
		"Call-ID: ctx-" + branch + "\r\n" +
		"CSeq: 1 " + method + "\r\n" +
		"Content-Length: 0\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func newTxServer(t *testing.T) *Server {
	t.Helper()
	s := NewServer(config.Default(), nil)
	s.timerT1Override = 10 * time.Millisecond
	return s
}

// Over UDP the request must be retransmitted until a final response arrives,
// and the final must be delivered to the waiter.
func TestClientTxRetransmitsOverUDPUntilFinal(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "retrans1"

	final := s.startClientTx(context.Background(), "udp", "192.0.2.20:5060", branch, "OPTIONS", txRequest("OPTIONS", branch), sender.send)

	deadline := time.Now().Add(2 * time.Second)
	for sender.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if sender.count() < 3 {
		t.Fatalf("only %d sends before the response; Timer E retransmission is not happening", sender.count())
	}

	if !s.dispatchClientResponse(txResponse(t, "200 OK", branch, "OPTIONS")) {
		t.Fatal("response was not claimed by the transaction")
	}

	select {
	case resp := <-final:
		if resp == nil || !strings.HasPrefix(resp.StartLine, "SIP/2.0 200") {
			t.Fatalf("final = %v, want the 200", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("final response never delivered to the waiter")
	}

	// Retransmission must stop once completed.
	settled := sender.count()
	time.Sleep(20 * s.t1())
	if sender.count() > settled {
		t.Fatalf("sends grew from %d to %d after the final response", settled, sender.count())
	}
}

// A reliable transport must send exactly once.
func TestClientTxDoesNotRetransmitOverTCP(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "tcp1"

	s.startClientTx(context.Background(), "tcp", "192.0.2.20:5060", branch, "OPTIONS", txRequest("OPTIONS", branch), sender.send)

	time.Sleep(20 * s.t1())
	if got := sender.count(); got != 1 {
		t.Fatalf("sends = %d over TCP, want exactly 1", got)
	}
}

// With no response at all the waiter must receive nil at Timer F.
func TestClientTxTimesOutWithNil(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "timeout1"

	final := s.startClientTx(context.Background(), "udp", "192.0.2.20:5060", branch, "NOTIFY", txRequest("NOTIFY", branch), sender.send)

	select {
	case resp := <-final:
		if resp != nil {
			t.Fatalf("expected nil on timeout, got %v", resp.StartLine)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("transaction never timed out (Timer F not firing)")
	}
}

// A provisional response stops INVITE retransmission (17.1.1.2) but must not
// complete the transaction.
func TestClientTxInviteStopsRetransmitOnProvisional(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "prov1"

	final := s.startClientTx(context.Background(), "udp", "192.0.2.20:5060", branch, "INVITE", txRequest("INVITE", branch), sender.send)

	if !s.dispatchClientResponse(txResponse(t, "180 Ringing", branch, "INVITE")) {
		t.Fatal("provisional was not claimed")
	}
	select {
	case <-final:
		t.Fatal("a provisional must not complete the transaction")
	case <-time.After(5 * s.t1()):
	}

	before := sender.count()
	time.Sleep(20 * s.t1())
	if after := sender.count(); after > before {
		t.Fatalf("INVITE kept retransmitting after a provisional: %d -> %d", before, after)
	}

	s.dispatchClientResponse(txResponse(t, "200 OK", branch, "INVITE"))
	select {
	case resp := <-final:
		if resp == nil {
			t.Fatal("final should be the 200, not a timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("final never delivered after provisional")
	}
}

// A non-2xx INVITE final must be ACKed by the transaction layer, with the ACK
// built per RFC 3261 17.1.1.3.
func TestClientTxAcksNon2xxInviteFinal(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "ack486"

	final := s.startClientTx(context.Background(), "udp", "192.0.2.20:5060", branch, "INVITE", txRequest("INVITE", branch), sender.send)

	s.dispatchClientResponse(txResponse(t, "486 Busy Here", branch, "INVITE"))
	select {
	case resp := <-final:
		if resp == nil || !strings.Contains(resp.StartLine, "486") {
			t.Fatalf("final = %v, want the 486", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("486 never delivered")
	}

	ack := sender.last()
	if !strings.HasPrefix(ack, "ACK sip:member@example.test SIP/2.0") {
		t.Fatalf("last wire write is not the ACK:\n%s", ack)
	}
	for _, want := range []string{
		"branch=" + branch,                          // same Via as the original request
		"To: <sip:member@example.test>;tag=member1", // To copied from the response, tag included
		"CSeq: 1 ACK",                               // original sequence number, method ACK
		"Call-ID: ctx-" + branch,
	} {
		if !strings.Contains(ack, want) {
			t.Fatalf("ACK missing %q:\n%s", want, ack)
		}
	}
}

// A retransmitted 486 after completion must be re-ACKed (the peer keeps
// retransmitting a final until it sees the ACK) without a second delivery to
// the waiter.
func TestClientTxReAcksRetransmittedFinal(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "reack1"

	final := s.startClientTx(context.Background(), "udp", "192.0.2.20:5060", branch, "INVITE", txRequest("INVITE", branch), sender.send)
	s.dispatchClientResponse(txResponse(t, "486 Busy Here", branch, "INVITE"))
	<-final

	acksBefore := 0
	sender.mu.Lock()
	for _, w := range sender.writes {
		if strings.HasPrefix(string(w), "ACK ") {
			acksBefore++
		}
	}
	sender.mu.Unlock()

	if !s.dispatchClientResponse(txResponse(t, "486 Busy Here", branch, "INVITE")) {
		t.Fatal("retransmitted final not claimed during linger")
	}

	acksAfter := 0
	sender.mu.Lock()
	for _, w := range sender.writes {
		if strings.HasPrefix(string(w), "ACK ") {
			acksAfter++
		}
	}
	sender.mu.Unlock()
	if acksAfter != acksBefore+1 {
		t.Fatalf("acks %d -> %d, want one more for the retransmitted final", acksBefore, acksAfter)
	}

	select {
	case extra := <-final:
		t.Fatalf("waiter received a second delivery: %v", extra)
	case <-time.After(5 * s.t1()):
	}
}

// Responses for a branch this server never sent must not be claimed.
func TestClientTxIgnoresUnknownBranch(t *testing.T) {
	s := newTxServer(t)
	if s.dispatchClientResponse(txResponse(t, "200 OK", rfc3261BranchCookie+"nobody", "OPTIONS")) {
		t.Fatal("claimed a response for a transaction that does not exist")
	}
}

// Same branch, different method: distinct transactions (17.1.3 matches on
// branch AND CSeq method).
func TestClientTxMatchesOnBranchAndMethod(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "shared"

	inviteFinal := s.startClientTx(context.Background(), "tcp", "t", branch, "INVITE", txRequest("INVITE", branch), sender.send)
	byeFinal := s.startClientTx(context.Background(), "tcp", "t", branch, "BYE", txRequest("BYE", branch), sender.send)

	s.dispatchClientResponse(txResponse(t, "200 OK", branch, "BYE"))
	select {
	case <-byeFinal:
	case <-time.After(2 * time.Second):
		t.Fatal("BYE final not delivered")
	}
	select {
	case <-inviteFinal:
		t.Fatal("the BYE response completed the INVITE transaction")
	case <-time.After(5 * s.t1()):
	}
}

// Cancelling the context must complete the waiter with nil rather than leaving
// the goroutine and the waiter hanging.
func TestClientTxContextCancellationCompletesNil(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "cancelctx"

	ctx, cancel := context.WithCancel(context.Background())
	final := s.startClientTx(ctx, "udp", "192.0.2.20:5060", branch, "NOTIFY", txRequest("NOTIFY", branch), sender.send)
	cancel()

	select {
	case resp := <-final:
		if resp != nil {
			t.Fatalf("expected nil after cancellation, got %v", resp.StartLine)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not complete the transaction")
	}
}

// End to end through handleRaw: an inbound response datagram reaches the
// transaction with no special plumbing at call sites.
func TestClientTxCompletedViaHandleRaw(t *testing.T) {
	s := newTxServer(t)
	sender := &countingSender{}
	branch := rfc3261BranchCookie + "viaraw"

	final := s.startClientTx(context.Background(), "udp", "192.0.2.20:5060", branch, "OPTIONS", txRequest("OPTIONS", branch), sender.send)

	raw := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=" + branch + "\r\n" +
		"From: <sip:mcptt-as@example.test>;tag=as1\r\n" +
		"To: <sip:member@example.test>;tag=m1\r\n" +
		"Call-ID: ctx-" + branch + "\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Content-Length: 0\r\n\r\n"
	s.handleRaw(context.Background(), "192.0.2.20:5060", "udp", []byte(raw), func([]byte) error { return nil })

	select {
	case resp := <-final:
		if resp == nil {
			t.Fatal("handleRaw did not route the response to the transaction")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response never reached the transaction through handleRaw")
	}
}

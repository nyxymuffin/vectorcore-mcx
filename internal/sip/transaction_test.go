package sip

import (
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
)

func requestWithBranch(t *testing.T, method, branch, sentBy string) *Message {
	t.Helper()
	raw := method + " sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + sentBy + ";branch=" + branch + ";rport\r\n" +
		"From: <sip:u@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: tx-1\r\n" +
		"CSeq: 1 " + method + "\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestServerTransactionKeyUsesBranchSentByAndMethod(t *testing.T) {
	msg := requestWithBranch(t, "INVITE", "z9hG4bKabc123", "192.0.2.52:5060")

	key, ok := serverTransactionKey(msg)
	if !ok {
		t.Fatal("an RFC 3261 branch must yield a transaction key")
	}
	if key.branch != "z9hG4bKabc123" {
		t.Fatalf("branch = %q", key.branch)
	}
	if key.sentBy != "192.0.2.52:5060" {
		t.Fatalf("sent-by = %q", key.sentBy)
	}
	if key.method != "INVITE" {
		t.Fatalf("method = %q", key.method)
	}
}

// RFC 2543 peers send a branch without the magic cookie. Matching those
// requires comparing whole requests, which is not implemented, so they must
// bypass the table rather than be matched incorrectly.
func TestServerTransactionKeyRejectsNonRFC3261Branch(t *testing.T) {
	for _, branch := range []string{"", "legacy-branch-1"} {
		msg := requestWithBranch(t, "INVITE", branch, "192.0.2.52:5060")
		if _, ok := serverTransactionKey(msg); ok {
			t.Fatalf("branch %q must not produce a transaction key", branch)
		}
	}
}

// A retransmitted request must be answered from the stored response instead of
// running the handler again. This is the failure that let a duplicated INVITE
// re-create the dialog and re-fire every group notification.
func TestRetransmissionIsAnsweredWithoutReprocessing(t *testing.T) {
	s := NewServer(config.Default(), nil)
	msg := requestWithBranch(t, "INVITE", "z9hG4bKdup1", "192.0.2.52:5060")

	var sent []string
	record := func(resp []byte) error {
		sent = append(sent, string(resp))
		return nil
	}

	// First delivery: handler runs and its response is captured.
	capture, proceed := s.beginServerTransaction(msg, record)
	if !proceed {
		t.Fatal("the first delivery must be processed")
	}
	if err := capture([]byte("SIP/2.0 200 OK\r\nCall-ID: tx-1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	// Retransmission: must be absorbed and answered from the transaction.
	_, proceed = s.beginServerTransaction(msg, record)
	if proceed {
		t.Fatal("a retransmission must not be processed again")
	}

	if len(sent) != 2 {
		t.Fatalf("responses sent = %d, want 2 (original plus replay)", len(sent))
	}
	if sent[0] != sent[1] {
		t.Fatalf("replayed response %q differs from the original %q", sent[1], sent[0])
	}
}

// While the first copy is still being handled there is no response to replay.
// Absorbing the duplicate is still correct: reprocessing would duplicate the
// side effects.
func TestRetransmissionDuringProcessingIsAbsorbedSilently(t *testing.T) {
	s := NewServer(config.Default(), nil)
	msg := requestWithBranch(t, "INVITE", "z9hG4bKinflight", "192.0.2.52:5060")

	var sent int
	count := func([]byte) error { sent++; return nil }

	if _, proceed := s.beginServerTransaction(msg, count); !proceed {
		t.Fatal("the first delivery must be processed")
	}
	if _, proceed := s.beginServerTransaction(msg, count); proceed {
		t.Fatal("a duplicate arriving before the response must not be processed")
	}
	if sent != 0 {
		t.Fatalf("sent %d responses, want 0: nothing exists to replay yet", sent)
	}
}

// Different methods on the same branch are different transactions. A CANCEL
// must not be answered with the INVITE's stored response.
func TestDifferentMethodsOnSameBranchAreDistinctTransactions(t *testing.T) {
	s := NewServer(config.Default(), nil)
	noop := func([]byte) error { return nil }

	invite := requestWithBranch(t, "INVITE", "z9hG4bKshared", "192.0.2.52:5060")
	cancel := requestWithBranch(t, "CANCEL", "z9hG4bKshared", "192.0.2.52:5060")

	if _, proceed := s.beginServerTransaction(invite, noop); !proceed {
		t.Fatal("INVITE must be processed")
	}
	if _, proceed := s.beginServerTransaction(cancel, noop); !proceed {
		t.Fatal("CANCEL shares the branch but is its own transaction and must be processed")
	}
}

func TestDifferentSentByAreDistinctTransactions(t *testing.T) {
	s := NewServer(config.Default(), nil)
	noop := func([]byte) error { return nil }

	a := requestWithBranch(t, "INVITE", "z9hG4bKsame", "192.0.2.52:5060")
	b := requestWithBranch(t, "INVITE", "z9hG4bKsame", "192.0.2.50:5060")

	if _, proceed := s.beginServerTransaction(a, noop); !proceed {
		t.Fatal("first peer must be processed")
	}
	if _, proceed := s.beginServerTransaction(b, noop); !proceed {
		t.Fatal("a different sent-by is a different transaction and must be processed")
	}
}

// The table is populated entirely from remote input, so it has to be reaped.
func TestReapTransactionsRemovesOnlyExpiredEntries(t *testing.T) {
	s := NewServer(config.Default(), nil)
	noop := func([]byte) error { return nil }

	old := requestWithBranch(t, "INVITE", "z9hG4bKold", "192.0.2.52:5060")
	fresh := requestWithBranch(t, "INVITE", "z9hG4bKfresh", "192.0.2.52:5060")
	s.beginServerTransaction(old, noop)
	s.beginServerTransaction(fresh, noop)

	now := time.Now()
	if removed := s.reapTransactions(now); removed != 0 {
		t.Fatalf("reaped %d fresh transactions, want 0", removed)
	}

	// Advance past the retention window.
	if removed := s.reapTransactions(now.Add(serverTransactionLifetime + time.Second)); removed != 2 {
		t.Fatalf("reaped %d expired transactions, want 2", removed)
	}

	// Reaped entries are gone, so the same request is processed afresh.
	if _, proceed := s.beginServerTransaction(old, noop); !proceed {
		t.Fatal("a request arriving after its transaction expired must be processed again")
	}
}

func TestViaSentByIgnoresParameters(t *testing.T) {
	cases := map[string]string{
		"SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKx;rport": "192.0.2.52:5060",
		"SIP/2.0/TCP host.example.test;branch=z9hG4bKy":     "host.example.test",
		"SIP/2.0/UDP 192.0.2.52":                            "192.0.2.52",
	}
	for via, want := range cases {
		if got := viaSentBy(via); got != want {
			t.Fatalf("viaSentBy(%q) = %q, want %q", via, got, want)
		}
	}
}

func TestViaParamIsCaseInsensitive(t *testing.T) {
	via := "SIP/2.0/UDP 192.0.2.52:5060;BRANCH=z9hG4bKmixed;rport"
	if got := viaParam(via, "branch"); got != "z9hG4bKmixed" {
		t.Fatalf("viaParam = %q, want the branch value regardless of case", got)
	}
	if got := viaParam(via, "missing"); got != "" {
		t.Fatalf("viaParam for an absent parameter = %q, want empty", got)
	}
}

func TestTransactionKeyIsIgnoredForResponses(t *testing.T) {
	// A response has no method on its start line, so it must not be keyed.
	raw := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKresp\r\n" +
		"CSeq: 1 INVITE\r\n\r\n"
	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := serverTransactionKey(msg); ok {
		t.Fatal("a response must not produce a server transaction key")
	}
}

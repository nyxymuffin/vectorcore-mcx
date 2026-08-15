package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Client transactions per RFC 3261 clause 17.1: outbound requests are
// retransmitted over unreliable transports until answered (Timer A for
// INVITE, Timer E for everything else), time out at 64*T1 (Timers B and F),
// and non-2xx INVITE final responses are ACKed by this layer (17.1.1.3).
// 2xx ACKs are the UAC core's job (clause 13) and are deliberately not
// handled here.
//
// Timer values from RFC 3261 Table 4 (Appendix A):
//
//	T1 500ms (RTT estimate), T2 4s (max non-INVITE retransmit interval),
//	T4 5s (max message lifetime in the network),
//	B = F = 64*T1, D > 32s for UDP, K = T4 for UDP; D and K are 0 on
//	reliable transports.
const (
	sipT1           = 500 * time.Millisecond
	sipT2           = 4 * time.Second
	sipT4           = 5 * time.Second
	sipTimerDLinger = 32 * time.Second
)

// clientTx is one client transaction. Matching is branch + CSeq method
// (RFC 3261 clause 17.1.3).
type clientTx struct {
	branch    string
	method    string
	transport string
	target    string
	raw       []byte
	request   *Message

	invite   bool
	reliable bool
	send     func([]byte) error

	// Final yields the final response exactly once, or nil on timeout or
	// context cancellation.
	Final chan *Message

	mu          sync.Mutex
	provisional bool
	completed   bool
	finalResp   *Message
}

func (s *Server) txKey(branch, method string) string {
	return branch + "|" + strings.ToUpper(method)
}

// t1 returns the base retransmission interval, shortened by tests through a
// per-server override so no global mutable state exists.
func (s *Server) t1() time.Duration {
	if s.timerT1Override > 0 {
		return s.timerT1Override
	}
	return sipT1
}

// sendTransacted sends a request inside a client transaction and returns the
// channel that will carry the final response (nil on timeout). The branch
// must be the RFC 3261 branch used in the request's topmost Via, and must be
// unique per transaction.
func (s *Server) sendTransacted(ctx context.Context, transport, target, branch, method string, raw []byte) <-chan *Message {
	send := func(b []byte) error { return s.sendOutbound(ctx, transport, target, b) }
	if s.clientTxSendOverride != nil {
		override := s.clientTxSendOverride
		send = func(b []byte) error { return override(transport, target, b) }
	}
	return s.startClientTx(ctx, transport, target, branch, method, raw, send)
}

// startClientTx registers the transaction, performs the first send, and runs
// the retransmission and timeout machinery. The send function is injectable
// so tests can count wire writes without sockets.
func (s *Server) startClientTx(ctx context.Context, transport, target, branch, method string, raw []byte, send func([]byte) error) <-chan *Message {
	method = strings.ToUpper(strings.TrimSpace(method))
	lower := strings.ToLower(strings.TrimSpace(transport))
	tx := &clientTx{
		branch:    branch,
		method:    method,
		transport: lower,
		target:    target,
		raw:       raw,
		invite:    method == "INVITE",
		reliable:  lower != "udp",
		send:      send,
		Final:     make(chan *Message, 1),
	}
	if req, err := Parse(raw); err == nil {
		tx.request = req
	}
	s.clientTx.Store(s.txKey(branch, method), tx)

	if err := send(raw); err != nil {
		slog.Warn("SIP client transaction initial send failed",
			"method", method, "target", target, "transport", lower, "err", err)
		s.finishClientTx(tx, nil)
		return tx.Final
	}
	go s.runClientTxTimers(ctx, tx)
	return tx.Final
}

// runClientTxTimers drives Timer A/E retransmission and the B/F timeout.
func (s *Server) runClientTxTimers(ctx context.Context, tx *clientTx) {
	t1 := s.t1()
	timeout := time.NewTimer(64 * t1)
	defer timeout.Stop()

	interval := t1
	var retrans *time.Timer
	if !tx.reliable {
		retrans = time.NewTimer(interval)
		defer retrans.Stop()
	} else {
		// Reliable transports never retransmit; only the timeout applies.
		retrans = time.NewTimer(time.Hour)
		retrans.Stop()
		defer retrans.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			s.finishClientTx(tx, nil)
			return
		case <-timeout.C:
			slog.Warn("SIP client transaction timed out",
				"method", tx.method, "branch", tx.branch, "target", tx.target)
			s.finishClientTx(tx, nil)
			return
		case <-retrans.C:
			tx.mu.Lock()
			done := tx.completed
			provisional := tx.provisional
			tx.mu.Unlock()
			if done {
				return
			}
			// An INVITE stops retransmitting once a provisional arrives
			// (17.1.1.2); a non-INVITE keeps going but pinned to T2
			// (17.1.2.2).
			if !(tx.invite && provisional) {
				if err := tx.send(tx.raw); err != nil {
					slog.Debug("SIP client retransmission failed",
						"method", tx.method, "branch", tx.branch, "err", err)
				}
			}
			if tx.invite {
				interval *= 2 // Timer A doubles without cap
			} else {
				interval *= 2 // Timer E doubles, capped at T2
				if interval > sipT2 {
					interval = sipT2
				}
				if provisional {
					interval = sipT2
				}
			}
			retrans.Reset(interval)
		}
	}
}

// dispatchClientResponse routes an inbound response to its client
// transaction. It reports whether a transaction claimed the response.
func (s *Server) dispatchClientResponse(msg *Message) bool {
	branch := viaParam(msg.Header("Via"), "branch")
	if !strings.HasPrefix(branch, rfc3261BranchCookie) {
		return false
	}
	fields := strings.Fields(msg.Header("CSeq"))
	if len(fields) < 2 {
		return false
	}
	method := strings.ToUpper(fields[len(fields)-1])
	v, ok := s.clientTx.Load(s.txKey(branch, method))
	if !ok {
		return false
	}
	tx := v.(*clientTx)

	status := responseStatusCode(msg)
	switch {
	case status >= 100 && status < 200:
		tx.mu.Lock()
		tx.provisional = true
		tx.mu.Unlock()
		return true
	case status >= 200:
		// A retransmitted final response after completion: re-ACK for
		// INVITE non-2xx (the far end did not see our ACK), swallow
		// otherwise.
		tx.mu.Lock()
		alreadyDone := tx.completed
		tx.mu.Unlock()
		if alreadyDone {
			if tx.invite && status >= 300 {
				s.ackNon2xx(tx, msg)
			}
			return true
		}
		if tx.invite && status >= 300 {
			s.ackNon2xx(tx, msg)
		}
		s.finishClientTx(tx, msg)
		return true
	}
	return false
}

// finishClientTx delivers the final result exactly once and schedules the
// transaction's removal after the response-retransmission linger (Timer D
// for INVITE over UDP, Timer K otherwise; immediate on reliable transports).
func (s *Server) finishClientTx(tx *clientTx, final *Message) {
	tx.mu.Lock()
	if tx.completed {
		tx.mu.Unlock()
		return
	}
	tx.completed = true
	tx.finalResp = final
	tx.mu.Unlock()

	tx.Final <- final

	linger := time.Duration(0)
	if !tx.reliable {
		if tx.invite {
			linger = sipTimerDLinger
		} else {
			linger = sipT4
		}
		if s.timerT1Override > 0 {
			// Tests shrink the linger with the same knob so they do not
			// wait wall-clock seconds for map cleanup.
			linger = 64 * s.timerT1Override
		}
	}
	key := s.txKey(tx.branch, tx.method)
	if linger == 0 {
		s.clientTx.Delete(key)
		return
	}
	time.AfterFunc(linger, func() { s.clientTx.Delete(key) })
}

// ackNon2xx builds and sends the transaction-layer ACK for a non-2xx final
// response, per RFC 3261 clause 17.1.1.3: Request-URI, Call-ID, From and CSeq
// sequence number from the original request; To from the response (it carries
// the tag); a single Via equal to the original request's top Via; Route
// copied from the original request.
func (s *Server) ackNon2xx(tx *clientTx, resp *Message) {
	if tx.request == nil {
		return
	}
	cseqNum := "1"
	if f := strings.Fields(tx.request.Header("CSeq")); len(f) > 0 {
		cseqNum = f[0]
	}
	hdrs := []header{
		{"Via", tx.request.Header("Via")},
		{"Max-Forwards", "70"},
		{"From", tx.request.Header("From")},
		{"To", resp.Header("To")},
		{"Call-ID", tx.request.Header("Call-ID")},
		{"CSeq", fmt.Sprintf("%s ACK", cseqNum)},
	}
	for _, route := range tx.request.HeadersFor("Route") {
		hdrs = append(hdrs, header{"Route", route})
	}
	ack := buildRequest("ACK", tx.request.URI, hdrs, nil)
	if err := tx.send([]byte(ack)); err != nil {
		slog.Debug("SIP non-2xx ACK send failed", "branch", tx.branch, "err", err)
	}
}

// responseStatusCode extracts the status code from a response start line.
func responseStatusCode(msg *Message) int {
	fields := strings.Fields(msg.StartLine)
	if len(fields) < 2 {
		return 0
	}
	code := 0
	for _, ch := range fields[1] {
		if ch < '0' || ch > '9' {
			return 0
		}
		code = code*10 + int(ch-'0')
	}
	return code
}

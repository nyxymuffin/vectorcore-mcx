package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// RFC 4028 session timer supervision. Every final response this server sends
// for an INVITE advertises "Session-Expires: 1800;refresher=uac" with
// "Require: timer" (TS 24.379 clause 6.3.3.2.3.2 item 6: the server starts
// supervising the session per RFC 4028 "UAS Behavior"). Until now nothing
// enforced it: a client that died mid-call left its call record, RX legs,
// floor grant and priority state behind forever. The reaper below sends the
// RFC 4028 clause 10 BYE when the session expires without a refresh.

// sessionExpiresSeconds is the advertised Session-Expires interval.
const sessionExpiresSeconds = 1800

const sessionExpiresHeader = "1800;refresher=uac"

// sessionInterval returns the supervision interval, shortened by tests via
// the per-server override (the timerT1Override pattern - a global would race).
func (s *Server) sessionInterval() time.Duration {
	if s.sessionExpiryOverride > 0 {
		return s.sessionExpiryOverride
	}
	return sessionExpiresSeconds * time.Second
}

// markSessionAnswered stamps the session expiration when a leg is answered.
func (s *Server) markSessionAnswered(ctx context.Context, callID string) {
	if err := s.st.RefreshCallSession(ctx, callID, time.Now().UTC().Add(s.sessionInterval())); err != nil {
		slog.Warn("session expiry stamp failed", "call_id", callID, "err", err)
	}
}

// StartSessionExpiry runs the RFC 4028 supervision loop: calls whose session
// expiration passed without a refresh are released with BYEs both ways.
func (s *Server) StartSessionExpiry(ctx context.Context) error {
	interval := 5 * time.Second
	if s.sessionReapIntervalOverride > 0 {
		interval = s.sessionReapIntervalOverride
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.reapExpiredSessions(ctx)
		}
	}
}

func (s *Server) reapExpiredSessions(ctx context.Context) {
	calls, err := s.st.ListCalls(ctx)
	if err != nil {
		slog.Warn("session reaper list failed", "err", err)
		return
	}
	now := time.Now().UTC()
	for _, call := range calls {
		if call.State == "terminated" || call.State == "cancelled" {
			continue
		}
		if call.SessionExpiresAt.IsZero() || now.Before(call.SessionExpiresAt) {
			continue
		}
		slog.Info("MCPTT session expired without refresh (RFC 4028)",
			"call_id", call.CallID, "state", call.State, "expired_at", call.SessionExpiresAt)
		s.releaseExpiredCall(ctx, call)
	}
}

// releaseExpiredCall sends the RFC 4028 clause 10 BYE for one leg and cleans
// the session state the way a client BYE would.
func (s *Server) releaseExpiredCall(ctx context.Context, call store.MCPTTCall) {
	if strings.EqualFold(strings.TrimSpace(call.InitiatorURI), strings.TrimSpace(s.cfg.MCX.SIPIdentity)) {
		// AS-initiated RX leg: the UAC BYE path already exists.
		s.sendRXBYE(ctx, call)
	} else {
		s.sendCallerBYE(ctx, call)
	}
	if err := s.st.UpdateCallState(ctx, call.CallID, "terminated"); err != nil {
		slog.Warn("session reaper state update failed", "call_id", call.CallID, "err", err)
	}
	if call.GroupURI != "" {
		s.controllingFor(call.GroupURI).ReleaseGroupLegs(call.GroupURI, call.CallID)
		s.releaseChatSessionIfEmpty(ctx, call.GroupURI)
		if peers, err := s.st.ListCallsByGroup(ctx, call.GroupURI); err == nil && len(peers) == 0 {
			s.setGroupPriorityState(call.GroupURI, "")
		}
	}
}

// sendCallerBYE terminates a client-originated leg from the UAS side: the
// dialog's local identity (the original To) with the local tag, toward the
// caller's remote target through the recorded route set.
func (s *Server) sendCallerBYE(ctx context.Context, call store.MCPTTCall) {
	transport := call.Transport
	if transport == "" {
		transport = "udp"
	}
	var routeSet []string
	if call.RouteSet != "" {
		routeSet = strings.Split(call.RouteSet, "\n")
	}
	target := call.SourceAddr
	if len(routeSet) > 0 {
		if addr := addrFromSIPURI(routeSet[0]); addr != "" {
			target = addr
		}
	} else if call.RemoteTarget != "" {
		if addr := addrFromSIPURI(call.RemoteTarget); addr != "" {
			target = addr
		}
	}
	if strings.TrimSpace(target) == "" {
		slog.Warn("caller BYE: no route to caller", "call_id", call.CallID)
		return
	}
	reqURI := call.RemoteTarget
	if reqURI == "" {
		reqURI = call.InitiatorURI
	}
	localURI := call.TargetURI
	if strings.TrimSpace(localURI) == "" {
		localURI = s.cfg.MCX.SIPIdentity
	}
	branch := rfc3261BranchCookie + newToken()
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(transport), advertiseHost(s.cfg), branch)},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", localURI, call.LocalTag)},
		{"To", fmt.Sprintf("<%s>;tag=%s", call.InitiatorURI, call.RemoteTag)},
		{"Call-ID", call.CallID},
		{"CSeq", "2 BYE"},
		{"User-Agent", productName},
	}
	for _, r := range routeSet {
		if strings.TrimSpace(r) != "" {
			hdrs = append(hdrs, header{"Route", r})
		}
	}
	bye := buildRequest("BYE", reqURI, hdrs, nil)
	slog.Info("caller BYE sending (session expired)", "call_id", call.CallID, "caller", call.InitiatorURI, "target", target)
	s.sendTransacted(ctx, transport, target, branch, "BYE", []byte(bye))
}

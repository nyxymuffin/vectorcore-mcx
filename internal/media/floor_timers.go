package media

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Timer T1 (End of RTP media), TS 24.380 clause 6.3.4.4.3: one instance per
// granted talker, restarted by every RTP packet from that talker (clause
// 6.3.4.4.5 step 2). On expiry the floor idles (single talker) or the silent
// talker leaves the granted set with a Floor Release Multi Talker message to
// the other participants (step 5). The per-call last_rtp_at the observer
// already maintains is the timer's clock; a sweep enforces the deadline.

// sweepSilentTalkers releases granted talkers whose RTP went silent for T1.
func (o *Observer) sweepSilentTalkers(ctx context.Context, pc net.PacketConn) {
	t1s := o.cfg.Media.FloorT1Seconds
	if t1s <= 0 {
		return
	}
	t1 := time.Duration(t1s) * time.Second
	calls, err := o.st.ListCalls(ctx)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, call := range calls {
		if call.State == "terminated" || call.State == "cancelled" {
			continue
		}
		if strings.TrimSpace(call.FloorHolder) == "" {
			continue
		}
		if call.FloorState != "granted" && call.FloorState != "taken" {
			continue
		}
		last := call.LastRTPAt
		if call.FloorGrantedAt.After(last) {
			last = call.FloorGrantedAt
		}
		if last.IsZero() || now.Sub(last) < t1 {
			continue
		}
		o.releaseSilentTalker(ctx, pc, call)
	}
}

func (o *Observer) releaseSilentTalker(ctx context.Context, pc net.PacketConn, call store.MCPTTCall) {
	// The guarded update releases only if the holder is still the one the
	// sweep observed; a racing grant or release wins otherwise.
	expected := call.FloorHolder
	applied, err := o.st.UpdateCallFloorState(ctx, call.CallID, store.FloorStateUpdate{
		State:        "idle",
		Event:        "t1_end_of_rtp_media",
		Subtype:      mcpttFloorIdle,
		SSRC:         call.FloorSSRC,
		ClearHolder:  true,
		ExpectHolder: &expected,
	})
	if err != nil || !applied {
		return
	}
	slog.Info("MCPTT floor revoked by T1 (end of RTP media)",
		"call_id", call.CallID, "holder", expected, "last_rtp_at", call.LastRTPAt)

	multiTalker, _ := o.groupFloorPolicy(ctx, call.GroupURI)
	var peers []store.MCPTTCall
	if strings.TrimSpace(call.GroupURI) != "" {
		peers, _ = o.st.ListCallsByGroup(ctx, call.GroupURI)
	}
	remaining := 0
	for _, talker := range grantedTalkerLegs(peers) {
		if talker.CallID != call.CallID {
			remaining++
		}
	}
	var notice []byte
	if multiTalker && remaining > 0 {
		// Clause 6.3.4.4.3 step 5 a: SSRC and User ID of the silent talker.
		notice = buildMCPTTFloorReleaseMultiTalker(o.legUser(call), call.FloorSSRC)
	} else {
		notice = buildMCPTTFloorIdle()
	}
	// Tell the silent talker and the other legs.
	if strings.TrimSpace(call.FloorControlIP) != "" && call.FloorControlPort != 0 {
		if dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(call.FloorControlIP, strconv.Itoa(call.FloorControlPort))); err == nil {
			if _, err := pc.WriteTo(notice, dst); err != nil {
				slog.Warn("MCPTT T1 notice send failed", "call_id", call.CallID, "err", err)
			}
		}
	}
	o.notifyFloorPeers(pc, peers, call.CallID, notice)
	// A freed floor goes to the head of the request queue (clause 6.3.4.4.4).
	o.queues.remove(queueKey(call), call.CallID)
	o.grantQueuedRequest(ctx, pc, call)
}

// --- T20 (Floor Granted re-send) and grant-duration revocation ---

// pendingGrant tracks a queued grant awaiting the participant's first RTP
// (clause 6.3.4.3.3: T20 runs to guarantee reliable delivery of a queued
// Floor Granted, C20 retransmissions).
type pendingGrant struct {
	callID string
	ssrc   uint32
	remote string
	packet []byte
	sentAt time.Time
	count  int
}

const (
	floorT20Seconds = 5 // matches <T20-floor-granted> in the service config
	floorC20        = 3 // matches <C20-floor-granted>
)

func (o *Observer) registerPendingGrant(callID string, ssrc uint32, remote string, packet []byte) {
	o.pendingMu.Lock()
	defer o.pendingMu.Unlock()
	o.pendingGrants[callID] = &pendingGrant{
		callID: callID, ssrc: ssrc, remote: remote,
		packet: append([]byte(nil), packet...), sentAt: time.Now().UTC(), count: 1,
	}
}

// clearPendingGrant drops the T20 supervision once the participant is heard
// from (RTP with the granted SSRC) or the leg's floor state moves on.
func (o *Observer) clearPendingGrant(callID string, ssrc uint32) {
	o.pendingMu.Lock()
	defer o.pendingMu.Unlock()
	if g, ok := o.pendingGrants[callID]; ok && (ssrc == 0 || g.ssrc == ssrc) {
		delete(o.pendingGrants, callID)
	}
}

// sweepPendingGrants retransmits queued Floor Granted messages every T20 up
// to C20 times, then gives up and idles the leg.
func (o *Observer) sweepPendingGrants(ctx context.Context, pc net.PacketConn) {
	now := time.Now().UTC()
	o.pendingMu.Lock()
	var resend, expired []*pendingGrant
	for _, g := range o.pendingGrants {
		if now.Sub(g.sentAt) < floorT20Seconds*time.Second {
			continue
		}
		if g.count >= floorC20 {
			expired = append(expired, g)
			delete(o.pendingGrants, g.callID)
			continue
		}
		g.count++
		g.sentAt = now
		resend = append(resend, g)
	}
	o.pendingMu.Unlock()

	for _, g := range resend {
		if dst, err := net.ResolveUDPAddr("udp", g.remote); err == nil {
			if _, err := pc.WriteTo(g.packet, dst); err != nil {
				slog.Warn("MCPTT T20 grant resend failed", "call_id", g.callID, "err", err)
			} else {
				slog.Info("MCPTT T20 grant resent", "call_id", g.callID, "attempt", g.count)
			}
		}
	}
	for _, g := range expired {
		slog.Info("MCPTT queued grant abandoned after C20 resends", "call_id", g.callID)
		expect := floorHolder(g.ssrc)
		if _, err := o.st.UpdateCallFloorState(ctx, g.callID, store.FloorStateUpdate{
			State: "idle", Event: "t20_expired", Subtype: mcpttFloorIdle,
			SSRC: g.ssrc, ClearHolder: true, ExpectHolder: &expect,
		}); err != nil {
			slog.Warn("MCPTT T20 expiry state update failed", "call_id", g.callID, "err", err)
		}
	}
}

// sweepOverlongTalkers revokes talkers that exceeded the advertised grant
// duration: Floor Revoke with cause #2 (media burst too long, clause
// 8.2.10.2), then the same release handling as a silent talker.
func (o *Observer) sweepOverlongTalkers(ctx context.Context, pc net.PacketConn) {
	limit := o.cfg.Media.FloorGrantDurationSeconds
	if limit <= 0 {
		return
	}
	calls, err := o.st.ListCalls(ctx)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, call := range calls {
		if call.State == "terminated" || call.State == "cancelled" {
			continue
		}
		if strings.TrimSpace(call.FloorHolder) == "" || call.FloorGrantedAt.IsZero() {
			continue
		}
		if call.FloorState != "granted" && call.FloorState != "taken" {
			continue
		}
		if now.Sub(call.FloorGrantedAt) < time.Duration(limit)*time.Second {
			continue
		}
		// Revoke toward the talker, then release like T1 does.
		if strings.TrimSpace(call.FloorControlIP) != "" && call.FloorControlPort != 0 {
			if dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(call.FloorControlIP, strconv.Itoa(call.FloorControlPort))); err == nil {
				if _, err := pc.WriteTo(buildMCPTTFloorRevoke(revokeCauseMediaBurstTooLong), dst); err != nil {
					slog.Warn("MCPTT floor revoke send failed", "call_id", call.CallID, "err", err)
				}
			}
		}
		slog.Info("MCPTT floor revoked: grant duration exceeded",
			"call_id", call.CallID, "holder", call.FloorHolder, "granted_at", call.FloorGrantedAt)
		o.releaseSilentTalker(ctx, pc, call)
	}
}

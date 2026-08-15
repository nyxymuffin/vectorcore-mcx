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
		notice = buildMCPTTFloorReleaseMultiTalker(call.FloorSSRC, o.legUser(call), call.FloorSSRC)
	} else {
		notice = buildMCPTTFloorIdle(call.FloorSSRC)
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

package media

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Floor request queueing, TS 24.380 clause 6.3.4.4.2 case b: when the
// requesting client negotiated queueing of floor requests (the "mc_queueing"
// fmtp attribute, clause 14.2.2) and the floor cannot be granted, the request
// is queued instead of denied and answered with a Floor Queue Position Info
// message (clause 8.2.12) carrying the Queue Info field (clause 8.2.3.5).
// When the floor frees up, the head of the queue is granted (clause
// 6.3.4.4.4 step handling of queued requests).
//
// The queue depth mirrors the <floor-control-queue><depth> the generated
// service configuration document advertises.

const floorQueueDepth = 10

// Queue Position Info special values, clause 8.2.3.5.
const (
	queuePositionNotQueued = 254
	queuePositionUnknown   = 255
)

type queuedFloorRequest struct {
	callID   string
	ssrc     uint32
	remote   string
	priority uint8
}

type floorQueues struct {
	mu     sync.Mutex
	queues map[string][]queuedFloorRequest
}

func newFloorQueues() *floorQueues {
	return &floorQueues{queues: map[string][]queuedFloorRequest{}}
}

func queueKey(call store.MCPTTCall) string {
	if g := strings.TrimSpace(call.GroupURI); g != "" {
		return strings.ToLower(g)
	}
	return call.CallID
}

// enqueue adds a request (keeping one entry per call+SSRC, newest priority
// wins) and returns its 1-based position, or 0 when the queue is full.
func (q *floorQueues) enqueue(key string, req queuedFloorRequest) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries := q.queues[key]
	for i, e := range entries {
		if e.callID == req.callID && e.ssrc == req.ssrc {
			entries[i].priority = req.priority
			return i + 1
		}
	}
	if len(entries) >= floorQueueDepth {
		return 0
	}
	q.queues[key] = append(entries, req)
	return len(q.queues[key])
}

// position returns the 1-based queue position of a request, or 0.
func (q *floorQueues) position(key string, callID string, ssrc uint32) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, e := range q.queues[key] {
		if e.callID == callID && e.ssrc == ssrc {
			return i + 1
		}
	}
	return 0
}

// pop removes and returns the head of the queue.
func (q *floorQueues) pop(key string) (queuedFloorRequest, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries := q.queues[key]
	if len(entries) == 0 {
		return queuedFloorRequest{}, false
	}
	head := entries[0]
	if len(entries) == 1 {
		delete(q.queues, key)
	} else {
		q.queues[key] = entries[1:]
	}
	return head, true
}

// remove drops a call's entries (call ended while queued).
func (q *floorQueues) remove(key, callID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries := q.queues[key]
	kept := entries[:0]
	for _, e := range entries {
		if e.callID != callID {
			kept = append(kept, e)
		}
	}
	if len(kept) == 0 {
		delete(q.queues, key)
	} else {
		q.queues[key] = kept
	}
}

// negotiatedQueueing reports whether the leg's SDP negotiated queueing of
// floor requests (clause 14.2.2).
func negotiatedQueueing(call store.MCPTTCall) bool {
	return strings.Contains(call.SDPOffer, "mc_queueing") ||
		strings.Contains(call.SDPAnswer, "mc_queueing")
}

// buildMCPTTQueuePositionInfo builds a Floor Queue Position Info message
// (clause 8.2.12) with the Queue Info field: position and priority.
func buildMCPTTQueuePositionInfo(position, priority uint8) []byte {
	var fields []byte
	fields = appendFloorField(fields, 3 /* Queue Info, table 8.2.3.1-2 */, []byte{position, priority})
	return floorMessage(mcpttQueuePosition, serverFloorSSRC, fields)
}

// grantQueuedRequest pops the queue for a call's group and grants the floor
// to the head whose leg is still alive. Returns true when a grant happened.
func (o *Observer) grantQueuedRequest(ctx context.Context, pc net.PacketConn, releasedCall store.MCPTTCall) bool {
	key := queueKey(releasedCall)
	for {
		head, ok := o.queues.pop(key)
		if !ok {
			return false
		}
		calls, err := o.st.ListCalls(ctx)
		if err != nil {
			return false
		}
		var target *store.MCPTTCall
		for _, c := range calls {
			if c.CallID == head.callID && c.State != "terminated" && c.State != "cancelled" {
				candidate := c
				target = &candidate
				break
			}
		}
		if target == nil {
			continue
		}
		expected := target.FloorHolder
		applied, err := o.st.UpdateCallFloorState(ctx, target.CallID, store.FloorStateUpdate{
			State:        "granted",
			Event:        floorEventName(mcpttFloorGranted),
			Subtype:      mcpttFloorGranted,
			SSRC:         head.ssrc,
			Holder:       floorHolder(head.ssrc),
			ExpectHolder: &expected,
		})
		if err != nil || !applied {
			continue
		}
		dst, err := net.ResolveUDPAddr("udp", head.remote)
		if err != nil {
			continue
		}
		granted := buildMCPTTFloorGranted(head.ssrc, o.cfg.Media.FloorGrantDurationSeconds, floorIndicatorNormal|floorIndicatorQueueing, head.priority)
		o.registerPendingGrant(head.callID, head.ssrc, head.remote, granted)
		if _, err := pc.WriteTo(granted, dst); err != nil {
			slog.Warn("MCPTT queued floor grant send failed", "call_id", head.callID, "dst", head.remote, "err", err)
		} else {
			slog.Info("MCPTT queued floor granted", "call_id", head.callID, "ssrc", head.ssrc, "queue_key", key)
		}
		if peers, err := o.st.ListCallsByGroup(ctx, releasedCall.GroupURI); err == nil {
			taken := buildMCPTTFloorTaken(head.ssrc, o.legUser(*target), floorIndicatorNormal, nil, nil)
			o.notifyFloorPeers(pc, peers, target.CallID, taken)
		}
		return true
	}
}

package media

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

func TestFloorQueueOrdering(t *testing.T) {
	q := newFloorQueues()
	if pos := q.enqueue("g", queuedFloorRequest{callID: "a", ssrc: 1}); pos != 1 {
		t.Fatalf("first enqueue position = %d, want 1", pos)
	}
	if pos := q.enqueue("g", queuedFloorRequest{callID: "b", ssrc: 2}); pos != 2 {
		t.Fatalf("second enqueue position = %d, want 2", pos)
	}
	// Re-request keeps the position.
	if pos := q.enqueue("g", queuedFloorRequest{callID: "a", ssrc: 1, priority: 5}); pos != 1 {
		t.Fatalf("re-enqueue position = %d, want 1", pos)
	}
	if pos := q.position("g", "b", 2); pos != 2 {
		t.Fatalf("position lookup = %d, want 2", pos)
	}
	head, ok := q.pop("g")
	if !ok || head.callID != "a" || head.priority != 5 {
		t.Fatalf("pop = %+v ok=%v, want call a with updated priority", head, ok)
	}
	q.remove("g", "b")
	if _, ok := q.pop("g"); ok {
		t.Fatal("queue should be empty after remove")
	}
}

func TestFloorQueueDepthLimit(t *testing.T) {
	q := newFloorQueues()
	for i := 0; i < floorQueueDepth; i++ {
		if pos := q.enqueue("g", queuedFloorRequest{callID: string(rune('a' + i)), ssrc: uint32(i)}); pos == 0 {
			t.Fatalf("enqueue %d unexpectedly full", i)
		}
	}
	if pos := q.enqueue("g", queuedFloorRequest{callID: "overflow", ssrc: 99}); pos != 0 {
		t.Fatalf("queue accepted beyond depth %d", floorQueueDepth)
	}
}

// fakePacketConn captures writes so floor responses can be asserted.
type fakePacketConn struct {
	writes []fakeWrite
}

type fakeWrite struct {
	to   string
	data []byte
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) { select {} }
func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.writes = append(f.writes, fakeWrite{to: addr.String(), data: append([]byte(nil), p...)})
	return len(p), nil
}
func (f *fakePacketConn) Close() error                       { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// A second requester that negotiated mc_queueing is queued with a Queue
// Position Info answer, and granted when the holder releases.
func TestQueuedFloorRequestGrantedOnRelease(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	cfg := config.Default()
	o := NewObserver(cfg, st)

	group := "sip:g1@example.test"
	holderSDP := "m=application 49172 udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n"
	for _, c := range []store.MCPTTCall{
		{CallID: "leg-holder", State: "answered", GroupURI: group,
			FloorControlIP: "127.0.0.1", FloorControlPort: 41001, SDPOffer: holderSDP},
		{CallID: "leg-queued", State: "answered", GroupURI: group,
			FloorControlIP: "127.0.0.1", FloorControlPort: 41002, SDPOffer: holderSDP},
	} {
		if _, err := st.UpsertCall(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	pc := &fakePacketConn{}
	req := func(ssrc uint32) []byte { return floorMessage(mcpttFloorRequest, ssrc, nil) }
	addr := func(port int) net.Addr { return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port} }

	// Holder takes the floor.
	o.recordPacket(ctx, pc, "floor", addr(41001), req(0x0000aaaa))
	if len(pc.writes) < 1 || pc.writes[0].data[0]&0x0f != mcpttFloorGranted {
		t.Fatalf("holder was not granted: %+v", pc.writes)
	}

	// Second leg requests: queued, not denied.
	pc.writes = nil
	o.recordPacket(ctx, pc, "floor", addr(41002), req(0x0000bbbb))
	if len(pc.writes) != 1 {
		t.Fatalf("expected exactly one response to the queued request, got %d", len(pc.writes))
	}
	resp, ok := parseMCPTTFloorEvent(pc.writes[0].data)
	if !ok || resp.Subtype != mcpttQueuePosition {
		t.Fatalf("subtype = %d, want Queue Position Info", resp.Subtype)
	}
	// Queue Info field: position 1.
	var position uint8
	walkFloorFields(pc.writes[0].data[12:], func(id byte, value []byte) {
		if id == 3 && len(value) >= 1 {
			position = value[0]
		}
	})
	if position != 1 {
		t.Fatalf("queue position = %d, want 1", position)
	}

	// Holder releases: the queued request is granted.
	pc.writes = nil
	o.recordPacket(ctx, pc, "floor", addr(41001), floorMessage(mcpttFloorRelease, 0x0000aaaa, nil))
	grantSeen := false
	for _, w := range pc.writes {
		if ev, ok := parseMCPTTFloorEvent(w.data); ok && ev.Subtype == mcpttFloorGranted && ev.SSRC == 0x0000bbbb {
			grantSeen = true
			if ev.Indicator&floorIndicatorQueueing == 0 {
				t.Fatalf("queued grant lacks the queueing indicator: %x", ev.Indicator)
			}
		}
	}
	if !grantSeen {
		t.Fatalf("queued participant was not granted after release; writes: %d", len(pc.writes))
	}

	queued, err := st.GetCall(ctx, "leg-queued")
	if err != nil || queued == nil {
		t.Fatal(err)
	}
	if queued.FloorState != "granted" {
		t.Fatalf("queued leg floor state = %q, want granted", queued.FloorState)
	}
}

// Without mc_queueing negotiation the second request is still denied.
func TestUnqueuedSecondRequestStillDenied(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	o := NewObserver(config.Default(), st)

	group := "sip:g2@example.test"
	for _, c := range []store.MCPTTCall{
		{CallID: "p-holder", State: "answered", GroupURI: group, FloorControlIP: "127.0.0.1", FloorControlPort: 42001},
		{CallID: "p-denied", State: "answered", GroupURI: group, FloorControlIP: "127.0.0.1", FloorControlPort: 42002},
	} {
		if _, err := st.UpsertCall(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	pc := &fakePacketConn{}
	addr := func(port int) net.Addr { return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port} }
	o.recordPacket(ctx, pc, "floor", addr(42001), floorMessage(mcpttFloorRequest, 1, nil))
	pc.writes = nil
	o.recordPacket(ctx, pc, "floor", addr(42002), floorMessage(mcpttFloorRequest, 2, nil))
	if len(pc.writes) != 1 {
		t.Fatalf("expected one deny, got %d writes", len(pc.writes))
	}
	if got := pc.writes[0].data[0] & 0x0f; got != mcpttFloorDeny {
		t.Fatalf("subtype = %d, want deny", got)
	}
}

package media

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Floor Granted per clause 8.2.5: server SSRC in the header, Duration,
// Floor Priority, the granted participant's audio SSRC (field 14) and the
// Floor Indicator.
func TestBuildMCPTTFloorGranted(t *testing.T) {
	packet := buildMCPTTFloorGranted(0x11223344, 45, floorIndicatorNormal, 7)

	if got := packet[0] & 0x1f; got != mcpttFloorGranted {
		t.Fatalf("subtype=%d, want %d", got, mcpttFloorGranted)
	}
	if packet[1] != rtcpPacketTypeAPP {
		t.Fatalf("packet type=%d, want %d", packet[1], rtcpPacketTypeAPP)
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != serverFloorSSRC {
		t.Fatalf("header ssrc=%x, want the server's %x", got, serverFloorSSRC)
	}
	if got := string(packet[8:12]); got != "MCPT" {
		t.Fatalf("app name=%q, want MCPT", got)
	}
	var duration uint16
	var priority uint8
	var grantedSSRC uint32
	var indicator uint16
	walkFloorFields(packet[12:], func(id byte, value []byte) {
		switch id {
		case fldDuration:
			duration = binary.BigEndian.Uint16(value[:2])
		case fldFloorPriority:
			priority = value[0]
		case fldAudioSSRC:
			grantedSSRC = binary.BigEndian.Uint32(value[:4])
		case fldFloorIndicator:
			indicator = binary.BigEndian.Uint16(value[:2])
		}
	})
	if duration != 45 || priority != 7 || grantedSSRC != 0x11223344 || indicator != floorIndicatorNormal {
		t.Fatalf("fields: duration=%d priority=%d ssrc=%x indicator=%x", duration, priority, grantedSSRC, indicator)
	}
}

// Floor Deny per clause 8.2.6 carries the mandatory Reject Cause field.
func TestBuildMCPTTFloorDeny(t *testing.T) {
	packet := buildMCPTTFloorDeny(rejectCauseAnotherHasPermission)
	if got := packet[0] & 0x1f; got != mcpttFloorDeny {
		t.Fatalf("subtype=%d, want %d", got, mcpttFloorDeny)
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != serverFloorSSRC {
		t.Fatalf("header ssrc=%x, want server", got)
	}
	var cause uint16
	walkFloorFields(packet[12:], func(id byte, value []byte) {
		if id == fldRejectCause {
			cause = binary.BigEndian.Uint16(value[:2])
		}
	})
	if cause != rejectCauseAnotherHasPermission {
		t.Fatalf("reject cause=%d, want 1", cause)
	}
}

// Floor Revoke per clause 8.2.10 with cause #2 (media burst too long).
func TestBuildMCPTTFloorRevoke(t *testing.T) {
	packet := buildMCPTTFloorRevoke(revokeCauseMediaBurstTooLong)
	if got := packet[0] & 0x1f; got != mcpttFloorRevoke {
		t.Fatalf("subtype=%d, want revoke", got)
	}
	var cause uint16
	walkFloorFields(packet[12:], func(id byte, value []byte) {
		if id == fldRejectCause {
			cause = binary.BigEndian.Uint16(value[:2])
		}
	})
	if cause != revokeCauseMediaBurstTooLong {
		t.Fatalf("cause=%d, want 2", cause)
	}
}

func TestBuildMCPTTFloorIdle(t *testing.T) {
	packet := buildMCPTTFloorIdle()
	if got := packet[0] & 0x1f; got != mcpttFloorIdle {
		t.Fatalf("subtype=%d, want %d", got, mcpttFloorIdle)
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != serverFloorSSRC {
		t.Fatalf("header ssrc=%x, want server", got)
	}
	if got := string(packet[8:12]); got != "MCPT" {
		t.Fatalf("app name=%q, want MCPT", got)
	}
}

func TestParseMCPTTFloorEvent(t *testing.T) {
	packet := floorMessage(mcpttFloorRequest, 0x01020304, nil)

	event, ok := parseMCPTTFloorEvent(packet)
	if !ok {
		t.Fatal("expected MCPTT floor event")
	}
	if event.Subtype != mcpttFloorRequest {
		t.Fatalf("subtype=%d, want request", event.Subtype)
	}
	if event.SSRC != 0x01020304 {
		t.Fatalf("ssrc=%x, want 01020304", event.SSRC)
	}
}

func TestFloorEventStateMapping(t *testing.T) {
	tests := []struct {
		subtype uint8
		event   string
		state   string
	}{
		{mcpttFloorRequest, "request", "requested"},
		{mcpttFloorGranted, "granted", "granted"},
		{mcpttFloorDeny, "denied", "denied"},
		{mcpttFloorRelease, "release", "released"},
		{mcpttFloorIdle, "idle", "idle"},
		{mcpttFloorRevoke, "revoked", "revoked"},
		{mcpttQueuePosition, "queue_position", "queued"},
	}
	for _, tt := range tests {
		if got := floorEventName(tt.subtype); got != tt.event {
			t.Fatalf("event subtype %d = %q, want %q", tt.subtype, got, tt.event)
		}
		if got := floorStateForEvent(tt.subtype, ""); got != tt.state {
			t.Fatalf("state subtype %d = %q, want %q", tt.subtype, got, tt.state)
		}
	}
	if got := floorStateForEvent(mcpttFloorAck, "granted"); got != "granted" {
		t.Fatalf("ACK should keep current state, got %q", got)
	}
	if got := floorStateForEvent(mcpttQueuePositionReq, "granted"); got != "granted" {
		t.Fatalf("queue position request should keep current floor state, got %q", got)
	}
}

func TestFloorCanGrant(t *testing.T) {
	if !floorCanGrant(store.MCPTTCall{}, 0x01020304) {
		t.Fatal("expected empty floor to grant")
	}
	if !floorCanGrant(store.MCPTTCall{FloorState: "granted", FloorHolder: "ssrc:01020304"}, 0x01020304) {
		t.Fatal("expected current holder to renew grant")
	}
	if floorCanGrant(store.MCPTTCall{FloorState: "granted", FloorHolder: "ssrc:01020304"}, 0x05060708) {
		t.Fatal("did not expect competing SSRC to receive grant")
	}
	if !floorCanGrant(store.MCPTTCall{FloorState: "released", FloorHolder: "ssrc:01020304"}, 0x05060708) {
		t.Fatal("expected released floor to grant")
	}
}

func TestFloorCanClearHolder(t *testing.T) {
	call := store.MCPTTCall{FloorState: "granted", FloorHolder: "ssrc:01020304"}
	if !floorCanClearHolder(call, 0x01020304) {
		t.Fatal("expected holder release to clear floor holder")
	}
	if floorCanClearHolder(call, 0x05060708) {
		t.Fatal("did not expect non-holder release to clear floor holder")
	}
	if !floorCanClearHolder(store.MCPTTCall{}, 0x05060708) {
		t.Fatal("expected empty holder to allow clear")
	}
	if got := floorHolderForUpdate(floorEvent{Subtype: mcpttFloorRelease, SSRC: 0x05060708}, "released", call.FloorHolder, false); got != call.FloorHolder {
		t.Fatalf("non-holder release holder update = %q, want %q", got, call.FloorHolder)
	}
	if got := floorHolderForUpdate(floorEvent{Subtype: mcpttFloorRelease, SSRC: 0x01020304}, "released", call.FloorHolder, true); got != "" {
		t.Fatalf("holder release holder update = %q, want empty", got)
	}
}

func TestAllowPostTerminateMedia(t *testing.T) {
	call := store.MCPTTCall{
		State:        "terminated",
		TerminatedAt: time.Now().Add(-2 * time.Second),
	}

	if !allowPostTerminateMedia("rtcp", call) {
		t.Fatal("expected recent RTCP to match terminated call")
	}
	if !allowPostTerminateMedia("floor", call) {
		t.Fatal("expected recent floor packet to match terminated call")
	}
	if allowPostTerminateMedia("rtp", call) {
		t.Fatal("did not expect RTP to match terminated call")
	}

	call.TerminatedAt = time.Now().Add(-6 * time.Second)
	if allowPostTerminateMedia("rtcp", call) {
		t.Fatal("did not expect stale RTCP to match terminated call")
	}
}

func TestRTPStatsFromPacket(t *testing.T) {
	packet := []byte{
		0x80, 0x00, 0x10, 0x00,
		0x00, 0x00, 0x20, 0x00,
		0x01, 0x02, 0x03, 0x04,
		0xff,
	}
	now := time.Now()

	stats, ok := rtpStatsFromPacket(packet, store.MCPTTCall{}, now)
	if !ok {
		t.Fatal("expected RTP stats")
	}
	if stats.PayloadType != 0 || stats.SSRC != 0x01020304 || stats.FirstSequence != 0x1000 || stats.LastSequence != 0x1000 || stats.LastTimestamp != 0x2000 {
		t.Fatalf("unexpected first stats: %+v", stats)
	}
	if stats.ExpectedPackets != 1 || stats.LostPackets != 0 {
		t.Fatalf("expected=1 lost=0, got expected=%d lost=%d", stats.ExpectedPackets, stats.LostPackets)
	}

	next := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(next[2:4], 0x1002)
	binary.BigEndian.PutUint32(next[4:8], 0x20a0)
	stats, ok = rtpStatsFromPacket(next, store.MCPTTCall{
		RTPPackets:       1,
		RTPSSRC:          0x01020304,
		RTPFirstSequence: 0x1000,
		RTPLastSequence:  0x1000,
		RTPLastTimestamp: 0x2000,
		LastRTPAt:        now.Add(-20 * time.Millisecond),
	}, now)
	if !ok {
		t.Fatal("expected second RTP stats")
	}
	if stats.ExpectedPackets != 3 || stats.LostPackets != 1 {
		t.Fatalf("expected gap loss, got expected=%d lost=%d", stats.ExpectedPackets, stats.LostPackets)
	}
}

func TestRTPAuthorizedForFloor(t *testing.T) {
	if !rtpAuthorizedForFloor(store.MCPTTCall{}, 0x01020304) {
		t.Fatal("expected RTP to be authorized without a floor holder")
	}
	if !rtpAuthorizedForFloor(store.MCPTTCall{FloorHolder: "ssrc:01020304"}, 0x01020304) {
		t.Fatal("expected holder SSRC to be authorized")
	}
	if rtpAuthorizedForFloor(store.MCPTTCall{FloorHolder: "ssrc:01020304"}, 0x05060708) {
		t.Fatal("did not expect non-holder SSRC to be authorized")
	}
}

package media

import (
	"encoding/binary"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// The TLV walk of clause 8.1.3: one-octet ID, one-octet length below ID 192,
// value, zero-padding to the four-octet boundary.
func TestWalkFloorFieldsParsesPaddedFields(t *testing.T) {
	var fields []byte
	fields = appendFloorField(fields, fldFloorPriority, []byte{7, 0})
	fields = appendFloorField(fields, fldUserID, []byte("sip:alice@example.test"))
	var ind [2]byte
	binary.BigEndian.PutUint16(ind[:], floorIndicatorNormal|floorIndicatorMultiTalker)
	fields = appendFloorField(fields, fldFloorIndicator, ind[:])

	if len(fields)%4 != 0 {
		t.Fatalf("fields not 4-octet aligned: %d", len(fields))
	}

	packet := floorMessage(mcpttFloorRequest, 0x01020304, fields)
	event, ok := parseMCPTTFloorEvent(packet)
	if !ok {
		t.Fatal("expected parse")
	}
	if !event.HasPriority || event.Priority != 7 {
		t.Fatalf("priority=%d has=%v, want 7", event.Priority, event.HasPriority)
	}
	if event.UserID != "sip:alice@example.test" {
		t.Fatalf("user id=%q", event.UserID)
	}
	if !event.HasIndicator || event.Indicator&floorIndicatorMultiTalker == 0 {
		t.Fatalf("indicator=%x has=%v, want I-bit set", event.Indicator, event.HasIndicator)
	}
}

// The acknowledgment-request x bit (table 8.2.2.1-1) must not change the
// message identity.
func TestParseMasksAckRequestBit(t *testing.T) {
	packet := floorMessage(0x10|mcpttFloorGranted, 0x01020304, nil)
	event, ok := parseMCPTTFloorEvent(packet)
	if !ok || event.Subtype != mcpttFloorGranted {
		t.Fatalf("subtype=%d ok=%v, want granted", event.Subtype, ok)
	}
}

func TestGrantedUsersRoundTrip(t *testing.T) {
	users := []string{"sip:alice@example.test", "sip:bob@example.test"}
	value := encodeGrantedUsers(users)
	got := decodeGrantedUsers(value)
	if len(got) != 2 || got[0] != users[0] || got[1] != users[1] {
		t.Fatalf("round trip = %v, want %v", got, users)
	}
}

// Floor Taken in a multi-talker scenario (clause 8.2.9): I-bit set, List of
// Granted Users and List of SSRCs present and aligned.
func TestBuildFloorTakenMultiTalker(t *testing.T) {
	users := []string{"sip:alice@example.test", "sip:bob@example.test"}
	ssrcs := []uint32{0x0a0b0c0d, 0x01020304}
	packet := buildMCPTTFloorTaken(0x11223344, users[0], floorIndicatorNormal|floorIndicatorMultiTalker, users, ssrcs)

	if len(packet)%4 != 0 {
		t.Fatalf("packet not 4-octet aligned: %d", len(packet))
	}
	event, ok := parseMCPTTFloorEvent(packet)
	if !ok || event.Subtype != mcpttFloorTaken {
		t.Fatalf("subtype=%d ok=%v, want taken", event.Subtype, ok)
	}
	if event.Indicator&floorIndicatorMultiTalker == 0 {
		t.Fatalf("indicator=%x, want I-bit", event.Indicator)
	}
	if len(event.GrantedUsers) != 2 || event.GrantedUsers[1] != users[1] {
		t.Fatalf("granted users = %v, want %v", event.GrantedUsers, users)
	}
	// The SSRC list field: count, spare, then 4-octet SSRCs in order.
	var gotSSRCs []uint32
	walkFloorFields(packet[12:], func(id byte, value []byte) {
		if id != fldSSRCList {
			return
		}
		count := int(value[0])
		rest := value[2:]
		for i := 0; i < count && len(rest) >= 4; i++ {
			gotSSRCs = append(gotSSRCs, binary.BigEndian.Uint32(rest[:4]))
			rest = rest[4:]
		}
	})
	if len(gotSSRCs) != 2 || gotSSRCs[0] != ssrcs[0] || gotSSRCs[1] != ssrcs[1] {
		t.Fatalf("ssrc list = %x, want %x", gotSSRCs, ssrcs)
	}
}

// A single-talker Floor Taken carries no talker-list fields.
func TestBuildFloorTakenSingleTalker(t *testing.T) {
	packet := buildMCPTTFloorTaken(0x11223344, "sip:alice@example.test", floorIndicatorNormal, nil, nil)
	event, ok := parseMCPTTFloorEvent(packet)
	if !ok || event.Subtype != mcpttFloorTaken {
		t.Fatalf("subtype=%d ok=%v, want taken", event.Subtype, ok)
	}
	if len(event.GrantedUsers) != 0 {
		t.Fatalf("granted users = %v, want none", event.GrantedUsers)
	}
}

// Floor Release Multi Talker (clause 8.2.14): subtype 15, the releasing
// user's ID and SSRC, I-bit set.
func TestBuildFloorReleaseMultiTalker(t *testing.T) {
	packet := buildMCPTTFloorReleaseMultiTalker("sip:bob@example.test", 0x01020304)
	event, ok := parseMCPTTFloorEvent(packet)
	if !ok || event.Subtype != mcpttFloorReleaseMultiTalker {
		t.Fatalf("subtype=%d ok=%v, want 15", event.Subtype, ok)
	}
	if event.UserID != "sip:bob@example.test" {
		t.Fatalf("user id=%q", event.UserID)
	}
	if event.Indicator&floorIndicatorMultiTalker == 0 {
		t.Fatalf("indicator=%x, want I-bit", event.Indicator)
	}
	var gotSSRC uint32
	walkFloorFields(packet[12:], func(id byte, value []byte) {
		if id == fldAudioSSRC && len(value) >= 4 {
			gotSSRC = binary.BigEndian.Uint32(value[:4])
		}
	})
	if gotSSRC != 0x01020304 {
		t.Fatalf("participant ssrc=%x, want 01020304", gotSSRC)
	}
}

// Clause 6.3.4.4.2 vs 6.3.4.4.7a: single-talker refuses while another leg
// talks; multi-talker grants up to the maximum and refuses beyond it.
func TestFloorArbitrate(t *testing.T) {
	call := store.MCPTTCall{CallID: "c1"}
	if !floorArbitrate(call, 0, false, 1) {
		t.Fatal("single-talker with idle group must grant")
	}
	if floorArbitrate(call, 1, false, 1) {
		t.Fatal("single-talker with an active talker must refuse")
	}
	if !floorArbitrate(call, 1, true, 2) {
		t.Fatal("multi-talker below the limit must grant")
	}
	if floorArbitrate(call, 2, true, 2) {
		t.Fatal("multi-talker at the limit must refuse")
	}
}

func TestGrantedTalkerLegs(t *testing.T) {
	peers := []store.MCPTTCall{
		{CallID: "a", FloorState: "granted", FloorHolder: "ssrc:01020304"},
		{CallID: "b", FloorState: "released", FloorHolder: ""},
		{CallID: "c", FloorState: "granted", FloorHolder: ""},
		{CallID: "d", FloorState: "taken", FloorHolder: "ssrc:0a0b0c0d"},
	}
	talkers := grantedTalkerLegs(peers)
	if len(talkers) != 2 || talkers[0].CallID != "a" || talkers[1].CallID != "d" {
		t.Fatalf("talkers = %+v, want legs a and d", talkers)
	}
}

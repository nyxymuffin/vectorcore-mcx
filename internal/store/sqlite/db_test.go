package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

func TestCallRTPStatsRoundTrip(t *testing.T) {
	st, err := Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	_, err = st.UpsertCall(ctx, store.MCPTTCall{
		CallID:         "call-1",
		State:          "established",
		AudioIP:        "192.0.2.10",
		AudioPort:      40000,
		LocalAudioPort: 40000,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = st.UpdateCallRTPStats(ctx, "call-1", store.RTPStatsUpdate{
		PayloadType:     0,
		SSRC:            0x01020304,
		FirstSequence:   10,
		LastSequence:    12,
		LastTimestamp:   160,
		ExpectedPackets: 3,
		LostPackets:     1,
		Jitter:          2.5,
	})
	if err != nil {
		t.Fatal(err)
	}

	call, err := st.GetCall(ctx, "call-1")
	if err != nil {
		t.Fatal(err)
	}
	if call.RTPSSRC != 0x01020304 || call.RTPFirstSequence != 10 || call.RTPLastSequence != 12 || call.RTPLostPackets != 1 || call.RTPJitter != 2.5 {
		t.Fatalf("unexpected RTP stats: %+v", call)
	}

	if err := st.IncrementCallMedia(ctx, "call-1", "rtp_rejected", 12); err != nil {
		t.Fatal(err)
	}
	call, err = st.GetCall(ctx, "call-1")
	if err != nil {
		t.Fatal(err)
	}
	if call.RTPRejectedPackets != 1 || call.RTPRejectedBytes != 12 {
		t.Fatalf("unexpected rejected RTP counters: %+v", call)
	}
}

func TestCallFloorStateRoundTrip(t *testing.T) {
	st, err := Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	_, err = st.UpsertCall(ctx, store.MCPTTCall{
		CallID:           "call-1",
		State:            "established",
		FloorControlIP:   "192.0.2.10",
		FloorControlPort: 40002,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = st.UpdateCallFloorState(ctx, "call-1", store.FloorStateUpdate{
		State:   "granted",
		Event:   "granted",
		Subtype: 1,
		SSRC:    0x01020304,
		Holder:  "ssrc:01020304",
	})
	if err != nil {
		t.Fatal(err)
	}

	call, err := st.GetCall(ctx, "call-1")
	if err != nil {
		t.Fatal(err)
	}
	if call.FloorState != "granted" || call.FloorLastEvent != "granted" || call.FloorLastSubtype != 1 || call.FloorSSRC != 0x01020304 {
		t.Fatalf("unexpected floor state: %+v", call)
	}
	if call.FloorHolder != "ssrc:01020304" {
		t.Fatalf("floor holder = %q, want ssrc:01020304", call.FloorHolder)
	}
	if call.FloorGrantedAt.IsZero() || call.FloorUpdatedAt.IsZero() {
		t.Fatalf("expected floor timestamps: %+v", call)
	}

	err = st.UpdateCallFloorState(ctx, "call-1", store.FloorStateUpdate{
		State:       "released",
		Event:       "release",
		Subtype:     4,
		SSRC:        0x01020304,
		ClearHolder: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	call, err = st.GetCall(ctx, "call-1")
	if err != nil {
		t.Fatal(err)
	}
	if call.FloorState != "released" || call.FloorHolder != "" || call.FloorReleasedAt.IsZero() {
		t.Fatalf("expected released floor with cleared holder: %+v", call)
	}
}

func TestMembershipAndAffiliationAreSeparate(t *testing.T) {
	st, err := Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	user, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:u@example.test", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:g@example.test", DisplayName: "Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	member, err := st.IsGroupMember(ctx, user.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if member {
		t.Fatal("user should not be a member before membership create")
	}
	if _, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{UserID: user.ID, GroupID: group.ID, State: "affiliated"}); err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Fatalf("expected non-member affiliation rejection, got %v", err)
	}

	membership, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: group.ID, Role: "MCPTT User"})
	if err != nil {
		t.Fatal(err)
	}
	member, err = st.IsGroupMember(ctx, user.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !member {
		t.Fatal("expected user to be a group member")
	}
	affiliation, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{UserID: user.ID, GroupID: group.ID, State: "affiliated"})
	if err != nil {
		t.Fatal(err)
	}
	affiliated, err := st.IsGroupAffiliated(ctx, user.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !affiliated {
		t.Fatal("expected user to be runtime affiliated")
	}
	if _, err := st.UpdateGroupAffiliation(ctx, affiliation.ID, store.GroupAffiliation{UserID: user.ID, GroupID: group.ID, State: "deaffiliated"}); err != nil {
		t.Fatal(err)
	}
	affiliated, err = st.IsGroupAffiliated(ctx, user.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if affiliated {
		t.Fatal("deaffiliated runtime state should not be active")
	}
	if err := st.DeleteGroupMembership(ctx, membership.ID); err != nil {
		t.Fatal(err)
	}
	member, err = st.IsGroupMember(ctx, user.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if member {
		t.Fatal("membership should be deleted")
	}
	affiliations, err := st.ListGroupAffiliations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(affiliations) != 0 {
		t.Fatalf("deleting membership should clear runtime affiliation, got %+v", affiliations)
	}
}

func TestGroupMembershipRoleUsesMCPTTParticipantType(t *testing.T) {
	st, err := Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	user, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:u@example.test", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:g@example.test", DisplayName: "Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: group.ID, Role: "member"}); err == nil || !strings.Contains(err.Error(), "unsupported MCPTT participant type") {
		t.Fatalf("expected shorthand role rejection, got %v", err)
	}
	membership, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: group.ID})
	if err != nil {
		t.Fatal(err)
	}
	if membership.Role != "MCPTT User" {
		t.Fatalf("default role = %q, want MCPTT User", membership.Role)
	}
}

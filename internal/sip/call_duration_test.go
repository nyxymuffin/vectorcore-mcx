package sip

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// TNG3 (TS 24.379 clause 6.3.3.5): a group call whose group document carries
// <on-network-maximum-duration> is released when the duration passes.
func TestTNG3ReleasesGroupCallAtMaxDuration(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()

	groups, _ := st.ListGroups(ctx)
	g := groups[0]
	g.MaxDurationSeconds = 1
	if _, err := st.UpdateGroup(ctx, g.ID, g); err != nil {
		t.Fatal(err)
	}

	responses := collectResponses(t, s, snapshotGroupInvite("tng3-1"))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}

	// Within the limit: untouched.
	s.reapExpiredSessions(ctx)
	call, _ := st.GetCall(ctx, "tng3-1")
	if call.State == "terminated" {
		t.Fatal("call reaped before TNG3 expiry")
	}

	time.Sleep(1100 * time.Millisecond)
	s.reapExpiredSessions(ctx)
	call, _ = st.GetCall(ctx, "tng3-1")
	if call.State != "terminated" {
		t.Fatalf("state = %q, want terminated after TNG3 expiry", call.State)
	}
}

// A group without <on-network-maximum-duration> runs no TNG3 (clause
// 6.3.3.5.1: the element absent means the timer is not started).
func TestNoTNG3WithoutMaxDuration(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()

	responses := collectResponses(t, s, snapshotGroupInvite("tng3-none"))
	if len(responses) != 3 {
		t.Fatalf("responses = %v", responses)
	}
	time.Sleep(50 * time.Millisecond)
	s.reapExpiredSessions(ctx)
	call, _ := st.GetCall(ctx, "tng3-none")
	if call.State == "terminated" {
		t.Fatal("call without a group maximum duration was reaped")
	}
}

// While the group is in the in-progress emergency state, TNG3 does not run
// (clause 6.3.3.5.2: TNG2 replaces it).
func TestTNG3SuppressedDuringEmergency(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()

	groups, _ := st.ListGroups(ctx)
	g := groups[0]
	g.MaxDurationSeconds = 1
	if _, err := st.UpdateGroup(ctx, g.ID, g); err != nil {
		t.Fatal(err)
	}

	responses := collectResponses(t, s, snapshotGroupInvite("tng3-emg"))
	if len(responses) != 3 {
		t.Fatalf("responses = %v", responses)
	}
	s.setGroupPriorityState("sip:test_group@example.test", "emergency")

	time.Sleep(1100 * time.Millisecond)
	s.reapExpiredSessions(ctx)
	call, _ := st.GetCall(ctx, "tng3-emg")
	if call.State == "terminated" {
		t.Fatal("TNG3 ran during an in-progress emergency")
	}
}

// The private call timer (clause 11.1.1.4.1 step 10) bounds private calls
// via sip.private_call.max_duration_seconds.
func TestPrivateCallTimerDeadline(t *testing.T) {
	s, _ := groupCallFixture(t)
	s.cfg.SIP.PrivateCall.MaxDurationSeconds = 30

	answered := time.Now().UTC().Add(-time.Minute)
	deadline, reason := s.maxDurationDeadline(callWithGroup("sip:mcptt-session-abc@host", answered), nil)
	if deadline.IsZero() || reason != "private call timer" {
		t.Fatalf("deadline=%v reason=%q, want private call timer", deadline, reason)
	}
	if !deadline.Equal(answered.Add(30 * time.Second)) {
		t.Fatalf("deadline = %v, want answered+30s", deadline)
	}

	// Ad hoc calls use the adhoc knob.
	s.cfg.SIP.Adhoc.MaxCallDurationSeconds = 60
	deadline, reason = s.maxDurationDeadline(callWithGroup("sip:mcptt-adhoc-xyz@host", answered), nil)
	if deadline.IsZero() || reason != "adhoc group call timer" {
		t.Fatalf("deadline=%v reason=%q, want adhoc group call timer", deadline, reason)
	}
}

func callWithGroup(groupURI string, answered time.Time) store.MCPTTCall {
	return store.MCPTTCall{GroupURI: groupURI, AnsweredAt: answered}
}

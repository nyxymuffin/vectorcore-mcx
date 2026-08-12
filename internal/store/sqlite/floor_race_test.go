package sqlite

import (
	"context"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

func newCallForFloor(t *testing.T) (*Store, context.Context) {
	t.Helper()
	st, err := Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	ctx := context.Background()
	if _, err := st.UpsertCall(ctx, store.MCPTTCall{
		CallID:   "call-1",
		State:    "established",
		GroupURI: "sip:group@example.test",
	}); err != nil {
		t.Fatal(err)
	}
	return st, ctx
}

// Floor arbitration decides from a snapshot, so two requests can both conclude
// the floor is free. The guarded update must let exactly one of them win.
func TestFloorGrantGuardAdmitsOnlyOneClaimant(t *testing.T) {
	st, ctx := newCallForFloor(t)

	unheld := ""
	grant := func(holder string) bool {
		applied, err := st.UpdateCallFloorState(ctx, "call-1", store.FloorStateUpdate{
			State:        "granted",
			Event:        "granted",
			Subtype:      1,
			Holder:       holder,
			ExpectHolder: &unheld,
		})
		if err != nil {
			t.Fatal(err)
		}
		return applied
	}

	if !grant("ssrc:aaaaaaaa") {
		t.Fatal("first claim on an unheld floor must succeed")
	}
	if grant("ssrc:bbbbbbbb") {
		t.Fatal("second claim must be refused: both callers saw an unheld floor, only one may hold it")
	}

	call, err := st.GetCall(ctx, "call-1")
	if err != nil {
		t.Fatal(err)
	}
	if call == nil {
		t.Fatal("call not found")
	}
	if call.FloorHolder != "ssrc:aaaaaaaa" {
		t.Fatalf("floor holder = %q, want the winner of the race", call.FloorHolder)
	}
}

// Without a guard the update is unconditional, which is what the previous
// behaviour relied on and must remain available for the non-arbitrating paths.
func TestFloorUpdateWithoutGuardAlwaysApplies(t *testing.T) {
	st, ctx := newCallForFloor(t)

	applied, err := st.UpdateCallFloorState(ctx, "call-1", store.FloorStateUpdate{
		State:  "granted",
		Event:  "granted",
		Holder: "ssrc:aaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("an unguarded update must report that it applied")
	}

	applied, err = st.UpdateCallFloorState(ctx, "call-1", store.FloorStateUpdate{
		State:  "granted",
		Event:  "granted",
		Holder: "ssrc:bbbbbbbb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("an unguarded update must still apply even when the holder changed")
	}
}

func TestFloorGrantGuardMatchesExistingHolder(t *testing.T) {
	st, ctx := newCallForFloor(t)

	unheld := ""
	if _, err := st.UpdateCallFloorState(ctx, "call-1", store.FloorStateUpdate{
		State: "granted", Event: "granted", Holder: "ssrc:aaaaaaaa", ExpectHolder: &unheld,
	}); err != nil {
		t.Fatal(err)
	}

	// A caller that correctly observed the current holder may proceed, which is
	// what a release or revoke by the holder relies on.
	current := "ssrc:aaaaaaaa"
	applied, err := st.UpdateCallFloorState(ctx, "call-1", store.FloorStateUpdate{
		State: "released", Event: "release", ClearHolder: true, ExpectHolder: &current,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("a guard matching the current holder must permit the update")
	}
}

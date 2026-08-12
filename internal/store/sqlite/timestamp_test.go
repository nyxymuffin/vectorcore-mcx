package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Timestamps are stored as TEXT and compared directly in SQL, so their textual
// order has to match their chronological order.
//
// time.RFC3339Nano strips trailing zeros, which made that false: it renders
// 0.5s as ".5Z" and 0.55s as ".55Z", and ".5Z" sorts after ".55Z" because 'Z'
// (0x5A) is greater than '5' (0x35). Expiry comparisons were therefore wrong
// for a sub-second window.
func TestFormatTimeOrdersLexicographicallyByTime(t *testing.T) {
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		earlier time.Time
		later   time.Time
	}{
		{"half second before longer fraction", base.Add(500 * time.Millisecond), base.Add(550 * time.Millisecond)},
		{"zero fraction before any fraction", base, base.Add(1 * time.Nanosecond)},
		{"whole second boundary", base.Add(999999999 * time.Nanosecond), base.Add(time.Second)},
		{"minute boundary", base.Add(59 * time.Second), base.Add(time.Minute)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := formatTime(tc.earlier), formatTime(tc.later)
			if a >= b {
				t.Fatalf("text order disagrees with time order: %q must sort before %q", a, b)
			}
		})
	}
}

func TestFormatTimeIsFixedWidth(t *testing.T) {
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	want := len(formatTime(base))

	for _, offset := range []time.Duration{
		0,
		1 * time.Nanosecond,
		500 * time.Millisecond,
		550 * time.Millisecond,
		999999999 * time.Nanosecond,
	} {
		got := formatTime(base.Add(offset))
		if len(got) != want {
			t.Fatalf("formatTime(%v) = %q, width %d, want %d; comparisons need a constant width", offset, got, len(got), want)
		}
	}
}

func TestFormatTimeNormalisesToUTC(t *testing.T) {
	zone := time.FixedZone("UTC+2", 2*60*60)
	local := time.Date(2026, 8, 12, 12, 0, 0, 0, zone)
	utc := local.UTC()

	if got, want := formatTime(local), formatTime(utc); got != want {
		t.Fatalf("formatTime(%v) = %q, want %q; a non-UTC zone would break text comparison", local, got, want)
	}
}

func TestParseTimeAcceptsLegacyVariableWidthValues(t *testing.T) {
	// Written by an earlier version via time.RFC3339Nano.
	legacy := "2026-08-12T10:00:00.5Z"

	got := parseTime(legacy)
	if got.IsZero() {
		t.Fatal("legacy timestamps must still parse, otherwise existing rows are unreadable")
	}
	if want := 500 * time.Millisecond; time.Duration(got.Nanosecond()) != want {
		t.Fatalf("fraction = %v, want %v", time.Duration(got.Nanosecond()), want)
	}
}

// Registration expiry compares expires_at as text, so a sub-second difference
// must be honoured rather than inverted.
func TestExpireRegistrationsHonoursSubSecondExpiry(t *testing.T) {
	st, err := Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

	// .5 expires before .55; the old format sorted them the other way round.
	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: "sip:early@example.test",
		Registered:     true,
		ExpiresAt:      base.Add(500 * time.Millisecond),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: "sip:late@example.test",
		Registered:     true,
		ExpiresAt:      base.Add(550 * time.Millisecond),
	}); err != nil {
		t.Fatal(err)
	}

	// A moment between the two: only the earlier registration has expired.
	n, err := st.ExpireRegistrations(ctx, base.Add(520*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expired %d registrations, want exactly 1; the sub-second comparison is inverted", n)
	}
}

// The migration must rewrite legacy rows, otherwise values written before and
// after the format change compare incorrectly against each other.
func TestMigrationNormalisesLegacyTimestamps(t *testing.T) {
	path := t.TempDir() + "/mcxas.db"
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: "sip:legacy@example.test",
		Registered:     true,
		ExpiresAt:      time.Date(2026, 8, 12, 10, 0, 0, 500000000, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	// Force the row back to the old variable-width representation.
	legacy := "2026-08-12T10:00:00.5Z"
	if _, err := st.db.ExecContext(ctx,
		st.q(`UPDATE mcptt_registrations SET expires_at = ? WHERE public_identity = ?`),
		legacy, "sip:legacy@example.test"); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Reopening runs the migration.
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()

	var stored string
	if err := st2.db.QueryRowContext(ctx,
		st2.q(`SELECT expires_at FROM mcptt_registrations WHERE public_identity = ?`),
		"sip:legacy@example.test").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == legacy {
		t.Fatal("legacy timestamp was not normalised by the migration")
	}
	if want := formatTime(parseTime(legacy)); stored != want {
		t.Fatalf("stored = %q, want canonical %q", stored, want)
	}
}

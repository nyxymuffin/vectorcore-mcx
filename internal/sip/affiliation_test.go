package sip

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

// affiliationPublish builds a clause 9.2.1.2 affiliation PUBLISH carrying the
// full desired group set.
func affiliationPublish(callID, expires string, groups []string) string {
	inner := ""
	for _, g := range groups {
		inner += `<affiliation group="` + g + `"/>`
	}
	pidf := `<presence entity="sip:caller@example.test"><tuple id="t1"><status>` +
		inner + `</status></tuple></presence>`
	expiresHdr := ""
	if expires != "" {
		expiresHdr = "Expires: " + expires + "\r\n"
	}
	return "PUBLISH sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKaf" + callID + "\r\n" +
		"From: <sip:caller@example.test>;tag=a1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 PUBLISH\r\n" +
		"Event: presence\r\n" +
		expiresHdr +
		"Content-Type: application/pidf+xml\r\n" +
		"Content-Length: " + fmt.Sprint(len(pidf)) + "\r\n\r\n" + pidf
}

// secondGroup provisions another group with the fixture caller as a member.
func secondGroup(t *testing.T, st *sqlite.Store, uri string) store.Group {
	t.Helper()
	ctx := context.Background()
	g, err := st.CreateGroup(ctx, store.Group{URI: uri, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	users, _ := st.ListUsers(ctx)
	for _, u := range users {
		if u.IMPU == "sip:caller@example.test" {
			if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
				UserID: u.ID, GroupID: g.ID, Role: "MCPTT User",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return g
}

// Clause 9.2.2.2.3 step 5: Expires must be 4294967295 or 0; anything else -
// including absent - is 423 with Min-Expires.
func TestAffiliationPublishWrongExpiresGets423(t *testing.T) {
	s, _ := groupCallFixture(t)
	for _, expires := range []string{"", "3600"} {
		responses := collectResponses(t, s, affiliationPublish("af423"+expires, expires, []string{"sip:test_group@example.test"}))
		if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 423") {
			t.Fatalf("Expires=%q: responses = %v, want 423", expires, responses)
		}
		if !strings.Contains(responses[0], "Min-Expires: 4294967295") {
			t.Fatalf("423 lacks Min-Expires:\n%s", responses[0])
		}
	}
}

// The pidf body is the full desired set: a group omitted from a later
// publication is de-affiliated (step 14 a ii); Expires 0 clears everything.
func TestAffiliationSetReconciliation(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()
	g2 := secondGroup(t, st, "sip:second_group@example.test")

	// Affiliate to both.
	responses := collectResponses(t, s, affiliationPublish("af-1", "4294967295",
		[]string{"sip:test_group@example.test", "sip:second_group@example.test"}))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 200", responses)
	}
	affs, _ := st.ListGroupAffiliations(ctx)
	if len(affs) != 2 {
		t.Fatalf("affiliations = %d, want 2 (fixture starts with 1 pre-seeded)", len(affs))
	}

	// Re-publish with only the second group: the first is de-affiliated.
	collectResponses(t, s, affiliationPublish("af-2", "4294967295",
		[]string{"sip:second_group@example.test"}))
	affs, _ = st.ListGroupAffiliations(ctx)
	if len(affs) != 1 || affs[0].GroupID != g2.ID {
		t.Fatalf("after reduction affiliations = %+v, want only the second group", affs)
	}

	// Expires 0 clears the rest.
	responses = collectResponses(t, s, affiliationPublish("af-3", "0", nil))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("expires-0 responses = %v, want 200", responses)
	}
	affs, _ = st.ListGroupAffiliations(ctx)
	if len(affs) != 0 {
		t.Fatalf("after Expires 0 affiliations = %+v, want none", affs)
	}
}

// The N2 limit truncates the candidate set (clause 9.2.2.2.3; provider
// policy keeps the first N2 listed).
func TestAffiliationN2Truncation(t *testing.T) {
	s, st := groupCallFixture(t)
	s.cfg.SIP.MaxAffiliationsN2 = 1
	secondGroup(t, st, "sip:second_group@example.test")

	collectResponses(t, s, affiliationPublish("af-n2", "4294967295",
		[]string{"sip:test_group@example.test", "sip:second_group@example.test"}))
	affs, _ := st.ListGroupAffiliations(context.Background())
	if len(affs) != 1 {
		t.Fatalf("affiliations = %d, want 1 (N2)", len(affs))
	}
}

// Implicit affiliation on a chat group join refuses beyond N2 with 486 and
// warning "102" (clause 10.1.2.4.1.1 step 6 via 9.2.2.3.7).
func TestChatImplicitAffiliationRespectsN2(t *testing.T) {
	s, st, _ := chatFixture(t)
	s.cfg.SIP.MaxAffiliationsN2 = 1
	ctx := context.Background()

	// The caller is already affiliated elsewhere, filling N2.
	other, err := st.CreateGroup(ctx, store.Group{URI: "sip:other@example.test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	users, _ := st.ListUsers(ctx)
	for _, u := range users {
		if u.IMPU == "sip:caller@example.test" {
			if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
				UserID: u.ID, GroupID: other.ID, Role: "MCPTT User",
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{
				UserID: u.ID, GroupID: other.ID, State: "affiliated",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	responses := collectResponses(t, s, chatInvite("chat-n2", "sip:caller@example.test"))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 486") {
		t.Fatalf("responses = %v, want exactly one 486", responses)
	}
	if !strings.Contains(responses[0], `"102 too many simultaneous affiliations"`) {
		t.Fatalf("486 lacks warning 102:\n%s", responses[0])
	}
}

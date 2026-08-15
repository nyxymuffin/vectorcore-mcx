package sip

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// regroupMessage builds a clause 16.2.1.1 create/remove request.
func regroupMessage(callID, action, tgi, preconfigured string, groups []string) string {
	body := `<mcpttregroupinfo xmlns="urn:3gpp:ns:mcpttRegroupInfo:1.0">` +
		`<regroup-action>` + action + `</regroup-action>` +
		`<mcptt-regroup-uri><mcpttURI>` + tgi + `</mcpttURI></mcptt-regroup-uri>`
	if preconfigured != "" {
		body += `<preconfigured-group><mcpttURI>` + preconfigured + `</mcpttURI></preconfigured-group>`
	}
	if len(groups) > 0 {
		body += `<groups-for-regroup>`
		for _, g := range groups {
			body += `<mcpttURI>` + g + `</mcpttURI>`
		}
		body += `</groups-for-regroup>`
	}
	body += `</mcpttregroupinfo>`
	return "MESSAGE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"From: <sip:caller@example.test>;tag=rg1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		"Content-Type: application/vnd.3gpp.mcptt-regroup+xml\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

// regroupFixture: the standard group plus a second one, both with the caller
// and a registered member affiliated.
func regroupFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s, st := groupCallFixture(t)
	ctx := context.Background()

	second, err := st.CreateGroup(ctx, store.Group{URI: "sip:group_b@example.test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	member, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:memberb@example.test", MCPTTID: "sip:memberb@example.test", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
		UserID: member.ID, GroupID: second.ID, Role: "MCPTT User",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{
		UserID: member.ID, GroupID: second.ID, State: "affiliated",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPublishedState(ctx, store.PublishedState{
		UserURI: "sip:memberb@example.test", Event: "poc-settings",
		Body: `<poc-settings><entity id="b"><am-settings><answer-mode>automatic</answer-mode></am-settings></entity></poc-settings>`,
	}); err != nil {
		t.Fatal(err)
	}
	return s, "sip:group_b@example.test"
}

// Create per clause 16.2.3.1, duplicate refused with warning 165, remove per
// 16.2.3.2, and removing an unknown TGI refused with 163.
func TestRegroupCreateAndRemove(t *testing.T) {
	s, groupB := regroupFixture(t)
	tgi := "sip:tgi-1@example.test"
	groups := []string{"sip:test_group@example.test", groupB}

	responses := collectResponses(t, s,
		regroupMessage("rg-1", "create", tgi, "sip:test_group@example.test", groups))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("create responses = %v, want 200", responses)
	}

	// Duplicate identity.
	responses = collectResponses(t, s,
		regroupMessage("rg-2", "create", tgi, "sip:test_group@example.test", groups))
	if len(responses) != 1 || !strings.Contains(responses[0], `"165 group ID for regroup already in use"`) {
		t.Fatalf("duplicate create = %v, want 403 with warning 165", responses)
	}

	// Remove.
	responses = collectResponses(t, s, regroupMessage("rg-3", "remove", tgi, "", nil))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("remove responses = %v, want 200", responses)
	}

	// Removing again: unknown identity.
	responses = collectResponses(t, s, regroupMessage("rg-4", "remove", tgi, "", nil))
	if len(responses) != 1 || !strings.Contains(responses[0], `"163 the group identity indicated in the request does not exist"`) {
		t.Fatalf("re-remove = %v, want 403 with warning 163", responses)
	}
}

// A regroup in an in-progress emergency state cannot be removed (step 2,
// warning 169).
func TestRegroupRemoveRefusedDuringEmergency(t *testing.T) {
	s, groupB := regroupFixture(t)
	tgi := "sip:tgi-emg@example.test"
	collectResponses(t, s, regroupMessage("rg-e1", "create", tgi,
		"sip:test_group@example.test", []string{"sip:test_group@example.test", groupB}))
	s.setGroupPriorityState(tgi, "emergency")

	responses := collectResponses(t, s, regroupMessage("rg-e2", "remove", tgi, "", nil))
	if len(responses) != 1 || !strings.Contains(responses[0], `"169 user not authorised to remove regroup in an emergency state"`) {
		t.Fatalf("responses = %v, want 403 with warning 169", responses)
	}
}

// While regrouped, a call to a constituent group is refused with warning 148;
// a call on the TGI reaches members of every constituent group.
func TestRegroupedConstituentRefusedAndTGICallFansOut(t *testing.T) {
	s, groupB := regroupFixture(t)
	tgi := "sip:tgi-2@example.test"
	collectResponses(t, s, regroupMessage("rg-5", "create", tgi,
		"sip:test_group@example.test", []string{"sip:test_group@example.test", groupB}))

	// The constituent group no longer takes calls.
	responses := collectResponses(t, s, snapshotGroupInvite("rg-call-1"))
	if len(responses) != 1 || !strings.Contains(responses[0], `"148 group is regrouped"`) {
		t.Fatalf("constituent call = %v, want 403 with warning 148", responses)
	}

	// A call on the TGI reaches group B's member.
	sock := registerAtSocket(t, s.st, "sip:memberb@example.test")

	tgiInvite := strings.ReplaceAll(snapshotGroupInvite("rg-call-2"),
		"sip:test_group@example.test", tgi)
	responses = collectResponses(t, s, tgiInvite)
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("TGI call = %v, want 100/180/200", responses)
	}

	buf := make([]byte, 8192)
	_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := sock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("constituent member never invited on the TGI call: %v", err)
	}
	leg := string(buf[:n])
	if !strings.Contains(leg, "INVITE sip:memberb@example.test") || !strings.Contains(leg, tgi) {
		t.Fatalf("TGI leg incomplete:\n%s", leg)
	}
}

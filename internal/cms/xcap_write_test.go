package cms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// httptestPut issues a PUT with an asserted identity.
func httptestPut(s *Server, target, body, identity string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, target, strings.NewReader(body))
	req.Header.Set("X-3GPP-Asserted-Identity", identity)
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)
	return rr
}

const groupDocBody = `<?xml version="1.0" encoding="UTF-8"?>
<group xmlns="urn:oma:xml:poc:list-service" xmlns:mcpttgi="urn:3gpp:ns:mcpttGroupInfo:1.0">
  <list-service uri="sip:written@example.test">
    <display-name xml:lang="en">Written Group</display-name>
    <list>
      <entry uri="sip:alice@example.test"/>
      <entry uri="sip:bob@example.test"><participant-type>MCPTT Administrator</participant-type></entry>
    </list>
    <mcpttgi:on-network-invite-members>true</mcpttgi:on-network-invite-members>
    <mcpttgi:multi-talker-control>true</mcpttgi:multi-talker-control>
    <mcpttgi:on-network-maximum-duration>PT600S</mcpttgi:on-network-maximum-duration>
  </list-service>
</group>`

// A group document PUT creates the group, its memberships, and every element
// the store models; GET returns the regenerated canonical document.
func TestGroupDocumentPutCreatesGroup(t *testing.T) {
	s, st := xcapFixture(t)
	ctx := context.Background()
	for _, impu := range []string{"sip:alice@example.test", "sip:bob@example.test"} {
		if _, err := st.CreateUser(ctx, store.User{IMPU: impu, MCPTTID: impu, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}

	rr := doXCAP(s, http.MethodPut,
		"/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:written@example.test", "", "", groupDocBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rr.Code, rr.Body.String())
	}

	groups, _ := st.ListGroups(ctx)
	if len(groups) != 1 {
		t.Fatalf("groups = %+v, want one", groups)
	}
	g := groups[0]
	if g.URI != "sip:written@example.test" || g.DisplayName != "Written Group" {
		t.Fatalf("group = %+v", g)
	}
	if g.ChatGroup {
		t.Fatal("on-network-invite-members true must mean prearranged (not chat)")
	}
	if !g.MultiTalker || g.MaxDurationSeconds != 600 {
		t.Fatalf("multi_talker=%v max_duration=%d, want true/600", g.MultiTalker, g.MaxDurationSeconds)
	}
	memberships, _ := st.ListGroupMemberships(ctx)
	if len(memberships) != 2 {
		t.Fatalf("memberships = %+v, want two", memberships)
	}
	roleOfBob := ""
	users, _ := st.ListUsers(ctx)
	for _, m := range memberships {
		for _, u := range users {
			if u.ID == m.UserID && u.IMPU == "sip:bob@example.test" {
				roleOfBob = m.Role
			}
		}
	}
	if roleOfBob != "MCPTT Administrator" {
		t.Fatalf("bob's role = %q, want MCPTT Administrator", roleOfBob)
	}

	// GET serves the regenerated document with the written elements.
	rr = doXCAP(s, http.MethodGet,
		"/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:written@example.test", "", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status = %d", rr.Code)
	}
	for _, want := range []string{
		"Written Group",
		"<mcpttgi:multi-talker-control>true</mcpttgi:multi-talker-control>",
		"<mcpttgi:on-network-maximum-duration>PT600S</mcpttgi:on-network-maximum-duration>",
		`uri="sip:alice@example.test"`,
	} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("regenerated document missing %q:\n%s", want, rr.Body.String())
		}
	}
}

// A member that is not a provisioned user refuses the whole document.
func TestGroupDocumentPutUnknownMemberRefused(t *testing.T) {
	s, st := xcapFixture(t)
	rr := doXCAP(s, http.MethodPut,
		"/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:written@example.test", "", "", groupDocBody)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for unknown members", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not a provisioned MC service user") {
		t.Fatalf("error body:\n%s", rr.Body.String())
	}
	groups, _ := st.ListGroups(context.Background())
	if len(groups) != 0 {
		t.Fatalf("refused PUT created a group: %+v", groups)
	}
}

// DELETE removes the group; a second DELETE is 404.
func TestGroupDocumentDelete(t *testing.T) {
	s, st := xcapFixture(t)
	ctx := context.Background()
	if _, err := st.CreateGroup(ctx, store.Group{URI: "sip:gone@example.test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rr := doXCAP(s, http.MethodDelete,
		"/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:gone@example.test", "", "", "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rr.Code)
	}
	groups, _ := st.ListGroups(ctx)
	if len(groups) != 0 {
		t.Fatalf("group not deleted: %+v", groups)
	}
	rr = doXCAP(s, http.MethodDelete,
		"/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:gone@example.test", "", "", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("re-delete status = %d, want 404", rr.Code)
	}
}

// A user-profile PUT updates the client-manageable fields (display name,
// FunctionalAliasList) and leaves provisioning-owned fields alone.
func TestUserProfilePutUpdatesAliasesAndDisplayName(t *testing.T) {
	s, st := xcapFixture(t)
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, store.User{
		IMPU: "sip:driver@example.test", MCPTTID: "sip:driver@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	profile := `<?xml version="1.0" encoding="UTF-8"?>
<mcptt-user-profile xmlns="urn:3gpp:mcptt:user-profile:1.0">
  <Common>
    <MCPTTUserID>
      <uri-entry>sip:driver@example.test</uri-entry>
      <display-name xml:lang="en">Lead Driver</display-name>
    </MCPTTUserID>
  </Common>
  <OnNetwork>
    <anyExt>
      <FunctionalAliasList>
        <entry><uri-entry>sip:leading-driver@example.test</uri-entry></entry>
        <entry><uri-entry>sip:conductor@example.test</uri-entry></entry>
      </FunctionalAliasList>
    </anyExt>
  </OnNetwork>
</mcptt-user-profile>`

	rr := doXCAP(s, http.MethodPut,
		"/xcap-root/org.3gpp.mcptt.user-profile/users/sip:driver@example.test/profile.xml", "", "", profile)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rr.Code, rr.Body.String())
	}

	users, _ := st.ListUsers(ctx)
	if len(users) != 1 {
		t.Fatal("user count changed")
	}
	u := users[0]
	if u.DisplayName != "Lead Driver" {
		t.Fatalf("display name = %q", u.DisplayName)
	}
	if len(u.FunctionalAliases) != 2 || u.FunctionalAliases[1] != "sip:conductor@example.test" {
		t.Fatalf("aliases = %v", u.FunctionalAliases)
	}
	if !u.Enabled {
		t.Fatal("provisioning-owned Enabled flag was touched")
	}
}

// With authorisation enforced, a bearer identity that is not an administrator
// member cannot modify an existing group.
func TestGroupDocumentModifyRequiresAdministrator(t *testing.T) {
	s, st := xcapFixture(t)
	ctx := context.Background()
	s.cfg.CMS.RequireAuthorization = true

	for _, impu := range []string{"sip:alice@example.test", "sip:bob@example.test"} {
		if _, err := st.CreateUser(ctx, store.User{IMPU: impu, MCPTTID: impu, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:written@example.test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	users, _ := st.ListUsers(ctx)
	for _, u := range users {
		role := "MCPTT User"
		if u.IMPU == "sip:bob@example.test" {
			role = "MCPTT Administrator"
		}
		if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
			UserID: u.ID, GroupID: group.ID, Role: role,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Alice (plain member) is refused; Bob (administrator) succeeds. The
	// identity arrives via X-3GPP-Asserted-Identity, the trusted-proxy
	// alternative of TS 24.482.
	req := func(identity string) int {
		r := httptestPut(s, "/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:written@example.test",
			groupDocBody, identity)
		return r.Code
	}
	if code := req("sip:alice@example.test"); code != http.StatusConflict {
		t.Fatalf("plain member modify = %d, want 409", code)
	}
	if code := req("sip:bob@example.test"); code != http.StatusNoContent {
		t.Fatalf("administrator modify = %d, want 204", code)
	}
}

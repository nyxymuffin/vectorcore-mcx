package cms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

func xcapFixture(t *testing.T) (*Server, *sqlite.Store) {
	t.Helper()
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewServer(config.Default(), st), st
}

func doXCAP(s *Server, method, target, ifMatch, ifNoneMatch, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, reader)
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)
	return rr
}

// RFC 4825 clause 6.3: a node selector after "~~" returns the addressed
// element as application/xcap-el+xml.
func TestNodeSelectorElementGet(t *testing.T) {
	s, st := xcapFixture(t)
	ctx := context.Background()
	if _, err := st.CreateGroup(ctx, store.Group{URI: "sip:g1@example.test", DisplayName: "Alpha", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	rr := doXCAP(s, http.MethodGet,
		"/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:g1@example.test/~~/group/list-service/display-name", "", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/xcap-el+xml" {
		t.Fatalf("content type = %q, want application/xcap-el+xml", ct)
	}
	if got := rr.Body.String(); !strings.Contains(got, ">Alpha<") || !strings.HasPrefix(got, "<display-name") {
		t.Fatalf("fragment = %q, want the display-name element", got)
	}
}

// A terminal @attr step returns the attribute value as
// application/xcap-att+xml.
func TestNodeSelectorAttributeGet(t *testing.T) {
	s, st := xcapFixture(t)
	if _, err := st.CreateGroup(context.Background(), store.Group{URI: "sip:g1@example.test", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	rr := doXCAP(s, http.MethodGet,
		"/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:g1@example.test/~~/group/list-service/@uri", "", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/xcap-att+xml" {
		t.Fatalf("content type = %q, want application/xcap-att+xml", ct)
	}
	if got := rr.Body.String(); got != "sip:g1@example.test" {
		t.Fatalf("attribute value = %q", got)
	}
}

// RFC 4825 clause 8.2.1: a selector that matches nothing is a 404.
func TestNodeSelectorNoMatchIs404(t *testing.T) {
	s, st := xcapFixture(t)
	if _, err := st.CreateGroup(context.Background(), store.Group{URI: "sip:g1@example.test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rr := doXCAP(s, http.MethodGet,
		"/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:g1@example.test/~~/group/no-such-element", "", "", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

// Attribute predicates address one entry among several (clause 6.3).
func TestNodeSelectorAttributePredicate(t *testing.T) {
	s, st := xcapFixture(t)
	ctx := context.Background()
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:g1@example.test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, impu := range []string{"sip:a@example.test", "sip:b@example.test"} {
		u, err := st.CreateUser(ctx, store.User{IMPU: impu, MCPTTID: impu, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
			UserID: u.ID, GroupID: group.ID, Role: "MCPTT User",
		}); err != nil {
			t.Fatal(err)
		}
	}

	rr := doXCAP(s, http.MethodGet,
		`/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:g1@example.test/~~/group/list-service/list/entry[@uri="sip:b@example.test"]`, "", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `uri="sip:b@example.test"`) || strings.Contains(body, "sip:a@example.test") {
		t.Fatalf("predicate selected the wrong entry:\n%s", body)
	}
}

// xcap-caps (RFC 4825 clause 12) lists the served application usages.
func TestXCAPCapsDocument(t *testing.T) {
	s, _ := xcapFixture(t)
	rr := doXCAP(s, http.MethodGet, "/xcap-root/xcap-caps/global/index", "", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/xcap-caps+xml" {
		t.Fatalf("content type = %q", ct)
	}
	for _, want := range []string{"<auid>org.openmobilealliance.groups</auid>", "<auid>org.3gpp.mcptt.user-profile</auid>", "urn:ietf:params:xml:ns:xcap-caps"} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("xcap-caps missing %q:\n%s", want, rr.Body.String())
		}
	}
}

// Unknown application usages are 404, not an invented document.
func TestUnknownAUIDIs404(t *testing.T) {
	s, _ := xcapFixture(t)
	rr := doXCAP(s, http.MethodGet, "/xcap-root/org.example.unknown/users/sip:x@example.test/doc.xml", "", "", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body:\n%s", rr.Code, rr.Body.String())
	}
}

// PUT of a generated document is refused with an xcap-error constraint
// failure instead of storing a shadow copy.
func TestPutGeneratedDocumentRefused(t *testing.T) {
	s, st := xcapFixture(t)
	rr := doXCAP(s, http.MethodPut, "/xcap-root/org.3gpp.mcptt.user-profile/users/sip:x@example.test/profile.xml", "", "", "<mcptt-user-profile/>")
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/xcap-error+xml" {
		t.Fatalf("content type = %q, want xcap-error", ct)
	}
	if !strings.Contains(rr.Body.String(), "<constraint-failure") {
		t.Fatalf("body lacks constraint-failure:\n%s", rr.Body.String())
	}
	docs, _ := st.ListCMSDocuments(context.Background())
	if len(docs) != 0 {
		t.Fatalf("refused PUT stored a document: %+v", docs)
	}
}

// Conditional PUT/DELETE, RFC 4825 clause 7.11.
func TestConditionalPutAndDelete(t *testing.T) {
	s, _ := xcapFixture(t)
	path := "/xcap-root/resource-lists/users/sip:x@example.test/index"

	// If-Match on a missing document fails.
	rr := doXCAP(s, http.MethodPut, path, `"whatever"`, "", "<resource-lists/>")
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("If-Match create: status = %d, want 412", rr.Code)
	}

	// Unconditional create.
	rr = doXCAP(s, http.MethodPut, path, "", "", "<resource-lists/>")
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201", rr.Code)
	}
	tag := rr.Header().Get("ETag")

	// If-None-Match: * against an existing document fails.
	rr = doXCAP(s, http.MethodPut, path, "", "*", "<resource-lists><list/></resource-lists>")
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("If-None-Match *: status = %d, want 412", rr.Code)
	}

	// If-Match with the current tag succeeds.
	rr = doXCAP(s, http.MethodPut, path, tag, "", "<resource-lists><list/></resource-lists>")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("If-Match update: status = %d, want 204", rr.Code)
	}

	// Delete with a stale tag fails; with the current tag it succeeds.
	rr = doXCAP(s, http.MethodDelete, path, tag, "", "")
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale delete: status = %d, want 412", rr.Code)
	}
	rr = doXCAP(s, http.MethodGet, path, "", "", "")
	current := rr.Header().Get("ETag")
	rr = doXCAP(s, http.MethodDelete, path, current, "", "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204", rr.Code)
	}
	// Deleting again is 404.
	rr = doXCAP(s, http.MethodDelete, path, "", "", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("re-delete: status = %d, want 404", rr.Code)
	}
}

// The byGroupID subdirectory of TS 24.481 table 7.2.10.2-1 resolves the
// group, and the generated document carries the supported-services and
// multi-talker markers.
func TestGroupDocumentByGroupIDWithMultiTalker(t *testing.T) {
	s, st := xcapFixture(t)
	if _, err := st.CreateGroup(context.Background(), store.Group{
		URI: "sip:g1@example.test", Enabled: true, MultiTalker: true, MaxSimultaneousTalkers: 3,
	}); err != nil {
		t.Fatal(err)
	}
	rr := doXCAP(s, http.MethodGet, "/xcap-root/org.openmobilealliance.groups/global/byGroupID/sip:g1@example.test", "", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`<list-service uri="sip:g1@example.test">`,
		`enabler="urn:urn-7:3gpp-service.ims.icsi.mcptt"`,
		"<mcpttgi:mcptt-speech/>",
		"<mcpttgi:multi-talker-control>true</mcpttgi:multi-talker-control>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("group document missing %q:\n%s", want, body)
		}
	}
}

// The generated user profile carries the FunctionalAliasList the SIP side
// authorises against (TS 24.484 clause 6.3.13.2.10).
func TestUserProfileCarriesFunctionalAliasList(t *testing.T) {
	s, st := xcapFixture(t)
	if _, err := st.CreateUser(context.Background(), store.User{
		IMPU: "sip:driver@example.test", MCPTTID: "sip:driver@example.test", Enabled: true,
		FunctionalAliases: []string{"sip:leading-driver@example.test"},
	}); err != nil {
		t.Fatal(err)
	}
	rr := doXCAP(s, http.MethodGet, "/xcap-root/org.3gpp.mcptt.user-profile/users/sip:driver@example.test/profile.xml", "", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<FunctionalAliasList>") ||
		!strings.Contains(body, "<uri-entry>sip:leading-driver@example.test</uri-entry>") {
		t.Fatalf("profile lacks FunctionalAliasList entry:\n%s", body)
	}
}

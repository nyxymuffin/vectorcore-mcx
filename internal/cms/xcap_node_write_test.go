package cms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

const listDoc = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">` +
	`<list name="team"><entry uri="sip:a@example.test"><display-name>A</display-name></entry></list>` +
	`</resource-lists>`

func seedDoc(t *testing.T, s *Server, path, body string) {
	t.Helper()
	if _, err := s.st.CreateCMSDocument(context.Background(), store.CMSDocument{
		Name: strings.Trim(path, "/"), AUID: auidFromPath(path), Path: path,
		ContentType: "application/resource-lists+xml", Body: body,
	}); err != nil {
		t.Fatal(err)
	}
}

func doNodeReq(s *Server, method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)
	return rr
}

const nodeBase = "/xcap-root/resource-lists/users/sip:x@example.test/index"

// Element PUT creates (201) then replaces (200) per RFC 4825 clauses
// 8.2.3/8.2.4, and the change is visible through a node GET.
func TestNodePutCreatesAndReplacesElement(t *testing.T) {
	s, _ := xcapFixture(t)
	seedDoc(t, s, "/resource-lists/users/sip:x@example.test/index", listDoc)

	sel := nodeBase + `/~~/resource-lists/list/entry[@uri="sip:b@example.test"]`
	rr := doNodeReq(s, http.MethodPut, sel, "application/xcap-el+xml",
		`<entry uri="sip:b@example.test"><display-name>B</display-name></entry>`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body: %s", rr.Code, rr.Body.String())
	}

	rr = doNodeReq(s, http.MethodGet, sel, "", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<display-name>B</display-name>") {
		t.Fatalf("node GET after create: %d %s", rr.Code, rr.Body.String())
	}

	// Replacing the same node is a 200.
	rr = doNodeReq(s, http.MethodPut, sel, "application/xcap-el+xml",
		`<entry uri="sip:b@example.test"><display-name>Bee</display-name></entry>`)
	if rr.Code != http.StatusOK {
		t.Fatalf("replace status = %d, want 200", rr.Code)
	}
	rr = doNodeReq(s, http.MethodGet, sel, "", "")
	if !strings.Contains(rr.Body.String(), "Bee") {
		t.Fatalf("replacement not visible: %s", rr.Body.String())
	}
	// The original entry survived.
	rr = doNodeReq(s, http.MethodGet, nodeBase, "", "")
	if !strings.Contains(rr.Body.String(), "sip:a@example.test") {
		t.Fatalf("sibling lost:\n%s", rr.Body.String())
	}
}

// Attribute PUT sets the value; a value that is not a legal AttValue is a
// 409 with <not-xml-att-value> (clause 8.2.2).
func TestNodePutAttribute(t *testing.T) {
	s, _ := xcapFixture(t)
	seedDoc(t, s, "/resource-lists/users/sip:x@example.test/index", listDoc)

	sel := nodeBase + "/~~/resource-lists/list/@name"
	rr := doNodeReq(s, http.MethodPut, sel, "application/xcap-att+xml", "squad")
	if rr.Code != http.StatusOK {
		t.Fatalf("attribute PUT status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	rr = doNodeReq(s, http.MethodGet, sel, "", "")
	if rr.Body.String() != "squad" {
		t.Fatalf("attribute = %q, want squad", rr.Body.String())
	}

	rr = doNodeReq(s, http.MethodPut, sel, "application/xcap-att+xml", `not"legal`)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "<not-xml-att-value") {
		t.Fatalf("illegal AttValue: %d %s", rr.Code, rr.Body.String())
	}
}

// A PUT whose parent cannot be resolved is a 409 with <no-parent>
// (clause 8.2.1).
func TestNodePutMissingParentIsNoParent(t *testing.T) {
	s, _ := xcapFixture(t)
	seedDoc(t, s, "/resource-lists/users/sip:x@example.test/index", listDoc)

	rr := doNodeReq(s, http.MethodPut,
		nodeBase+`/~~/resource-lists/nosuch/entry[@uri="sip:c@example.test"]`,
		"application/xcap-el+xml", `<entry uri="sip:c@example.test"/>`)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "<no-parent") {
		t.Fatalf("missing parent: %d %s", rr.Code, rr.Body.String())
	}

	// A PUT into a document that does not exist is also <no-parent>.
	rr = doNodeReq(s, http.MethodPut,
		"/xcap-root/resource-lists/users/sip:ghost@example.test/index/~~/resource-lists/list",
		"application/xcap-el+xml", `<list/>`)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "<no-parent") {
		t.Fatalf("missing document: %d %s", rr.Code, rr.Body.String())
	}
}

// DELETE removes the node and is idempotent: the second attempt is 404
// (clause 8.2.5).
func TestNodeDeleteIsIdempotent(t *testing.T) {
	s, _ := xcapFixture(t)
	seedDoc(t, s, "/resource-lists/users/sip:x@example.test/index", listDoc)

	sel := nodeBase + `/~~/resource-lists/list/entry[@uri="sip:a@example.test"]`
	rr := doNodeReq(s, http.MethodDelete, sel, "", "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204; body: %s", rr.Code, rr.Body.String())
	}
	rr = doNodeReq(s, http.MethodDelete, sel, "", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404", rr.Code)
	}

	// The list element itself survived the entry deletion.
	rr = doNodeReq(s, http.MethodGet, nodeBase+"/~~/resource-lists/list", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list gone after entry delete: %d", rr.Code)
	}
}

// Attribute DELETE drops just the attribute.
func TestNodeDeleteAttribute(t *testing.T) {
	s, _ := xcapFixture(t)
	seedDoc(t, s, "/resource-lists/users/sip:x@example.test/index", listDoc)

	sel := nodeBase + "/~~/resource-lists/list/@name"
	if rr := doNodeReq(s, http.MethodDelete, sel, "", ""); rr.Code != http.StatusNoContent {
		t.Fatalf("attribute delete = %d, want 204", rr.Code)
	}
	if rr := doNodeReq(s, http.MethodGet, sel, "", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("attribute still present: %d %s", rr.Code, rr.Body.String())
	}
	if rr := doNodeReq(s, http.MethodGet, nodeBase+"/~~/resource-lists/list", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("list element damaged by attribute delete: %d", rr.Code)
	}
}

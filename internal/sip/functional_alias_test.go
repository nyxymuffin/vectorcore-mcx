package sip

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

func faPublish(servedID, alias, expires string) string {
	info := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		`<mcptt-request-uri><mcpttURI>` + servedID + `</mcpttURI></mcptt-request-uri>` +
		`</mcptt-Params></mcpttinfo>`
	pidf := `<presence entity="` + servedID + `"><p-id-fa>pub-1</p-id-fa><tuple id="t1"><status>` +
		`<functionalAlias functionalAliasID="` + alias + `"/>` +
		`</status></tuple></presence>`
	body := "--fa\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + info +
		"\r\n--fa\r\nContent-Type: application/pidf+xml\r\n\r\n" + pidf + "\r\n--fa--\r\n"
	expiresHdr := ""
	if expires != "" {
		expiresHdr = "Expires: " + expires + "\r\n"
	}
	return "PUBLISH sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKfa" + alias + expires + "\r\n" +
		"From: <" + servedID + ">;tag=fa1\r\n" +
		"P-Asserted-Identity: <" + servedID + ">\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: fa-" + alias + "-" + expires + "\r\n" +
		"CSeq: 1 PUBLISH\r\n" +
		"Event: presence\r\n" +
		expiresHdr +
		`Content-Type: multipart/mixed;boundary="fa"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

func faFixture(t *testing.T) (*Server, *sqlite.Store) {
	t.Helper()
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.CreateUser(context.Background(), store.User{
		IMPU: "sip:driver@example.test", MCPTTID: "sip:driver@example.test", Enabled: true,
		FunctionalAliases: []string{"sip:leading-driver@example.test"},
	}); err != nil {
		t.Fatal(err)
	}
	return NewServer(config.Default(), st), st
}

func publishFA(t *testing.T, s *Server, raw string) string {
	t.Helper()
	var response string
	s.handleRaw(context.Background(), "192.0.2.52:5060", "udp", []byte(raw), func(b []byte) error {
		response = string(b)
		return nil
	})
	return response
}

// Activation per clause 9A.2.2.2.3: Expires 4294967295, alias in the user's
// FunctionalAliasList, state recorded as activated. Previously this exact
// PUBLISH was answered 200 and silently discarded.
func TestFunctionalAliasActivation(t *testing.T) {
	s, st := faFixture(t)

	resp := publishFA(t, s, faPublish("sip:driver@example.test", "sip:leading-driver@example.test", "4294967295"))
	if !strings.HasPrefix(resp, "SIP/2.0 200") {
		t.Fatalf("response = %q, want 200", firstLine(resp))
	}

	statuses, err := st.ListFunctionalAliasStatuses(context.Background(), "sip:driver@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].Status != "activated" {
		t.Fatalf("statuses = %+v, want one activated entry", statuses)
	}
	if statuses[0].AliasURI != "sip:leading-driver@example.test" {
		t.Fatalf("alias = %q", statuses[0].AliasURI)
	}
	if statuses[0].PIDFA != "pub-1" {
		t.Fatalf("p-id-fa = %q, want the publication identifier stored", statuses[0].PIDFA)
	}
}

func TestFunctionalAliasDeactivation(t *testing.T) {
	s, st := faFixture(t)
	publishFA(t, s, faPublish("sip:driver@example.test", "sip:leading-driver@example.test", "4294967295"))

	resp := publishFA(t, s, faPublish("sip:driver@example.test", "sip:leading-driver@example.test", "0"))
	if !strings.HasPrefix(resp, "SIP/2.0 200") {
		t.Fatalf("response = %q, want 200", firstLine(resp))
	}

	statuses, _ := st.ListFunctionalAliasStatuses(context.Background(), "sip:driver@example.test")
	if len(statuses) != 1 || statuses[0].Status != "deactivated" {
		t.Fatalf("statuses = %+v, want deactivated", statuses)
	}
}

// Clause 9A.2.2.2.3 step 5: any Expires other than 4294967295 or 0 -
// including absent - is answered 423 with Min-Expires.
func TestFunctionalAliasWrongExpiresGets423(t *testing.T) {
	s, _ := faFixture(t)

	for _, expires := range []string{"3600", ""} {
		resp := publishFA(t, s, faPublish("sip:driver@example.test", "sip:leading-driver@example.test", expires))
		if !strings.HasPrefix(resp, "SIP/2.0 423") {
			t.Fatalf("Expires=%q: response = %q, want 423", expires, firstLine(resp))
		}
		if !strings.Contains(resp, "Min-Expires: 4294967295") {
			t.Fatalf("423 lacks Min-Expires:\n%s", resp)
		}
	}
}

// Step 4A/4B: an alias outside the user's FunctionalAliasList is refused with
// warning "201".
func TestFunctionalAliasUnauthorisedAliasGets403With201(t *testing.T) {
	s, st := faFixture(t)

	resp := publishFA(t, s, faPublish("sip:driver@example.test", "sip:controller@example.test", "4294967295"))
	if !strings.HasPrefix(resp, "SIP/2.0 403") {
		t.Fatalf("response = %q, want 403", firstLine(resp))
	}
	if !strings.Contains(resp, `"201 user not authorized to change the functional alias status"`) {
		t.Fatalf("403 lacks warning 201:\n%s", resp)
	}
	statuses, _ := st.ListFunctionalAliasStatuses(context.Background(), "sip:driver@example.test")
	if len(statuses) != 0 {
		t.Fatalf("refused activation must store nothing: %+v", statuses)
	}
}

// Step 4: the originator must be the served user.
func TestFunctionalAliasForAnotherUserGets403(t *testing.T) {
	s, _ := faFixture(t)

	raw := strings.Replace(
		faPublish("sip:driver@example.test", "sip:leading-driver@example.test", "4294967295"),
		"P-Asserted-Identity: <sip:driver@example.test>",
		"P-Asserted-Identity: <sip:impostor@example.test>", 1)
	raw = strings.Replace(raw, "From: <sip:driver@example.test>;tag=fa1",
		"From: <sip:impostor@example.test>;tag=fa1", 1)

	resp := publishFA(t, s, raw)
	if !strings.HasPrefix(resp, "SIP/2.0 403") {
		t.Fatalf("response = %q, want 403 for a third-party change", firstLine(resp))
	}
}

// The affiliation path must be untouched by the FA discriminator.
func TestAffiliationPublishStillWorks(t *testing.T) {
	s, st := faFixture(t)
	ctx := context.Background()

	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:g1@example.test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	users, _ := st.ListUsers(ctx)
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{
		UserID: users[0].ID, GroupID: group.ID, Role: "MCPTT User",
	}); err != nil {
		t.Fatal(err)
	}

	pidf := `<presence entity="sip:driver@example.test"><tuple id="t1"><status>` +
		`<affiliation group="sip:g1@example.test"/>` +
		`</status></tuple></presence>`
	raw := "PUBLISH sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKaffil1\r\n" +
		"From: <sip:driver@example.test>;tag=a1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: affil-1\r\n" +
		"CSeq: 1 PUBLISH\r\n" +
		"Event: presence\r\n" +
		"Expires: 4294967295\r\n" +
		"Content-Type: application/pidf+xml\r\n" +
		"Content-Length: " + fmt.Sprint(len(pidf)) + "\r\n\r\n" + pidf

	resp := publishFA(t, s, raw)
	if !strings.HasPrefix(resp, "SIP/2.0 200") {
		t.Fatalf("affiliation publish broke: %q", firstLine(resp))
	}
}

// An unknown or absent SUBSCRIBE event package is 489, not silently answered
// with affiliation data.
func TestSubscribeUnknownEventGets489(t *testing.T) {
	s, _ := faFixture(t)

	for _, event := range []string{"Event: conference\r\n", ""} {
		raw := "SUBSCRIBE sip:mcptt-as@example.test SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKsub" + fmt.Sprint(len(event)) + "\r\n" +
			"From: <sip:driver@example.test>;tag=s1\r\n" +
			"To: <sip:mcptt-as@example.test>\r\n" +
			"Call-ID: sub-evt-" + fmt.Sprint(len(event)) + "\r\n" +
			"CSeq: 1 SUBSCRIBE\r\n" +
			event +
			"Expires: 3600\r\n" +
			"Content-Length: 0\r\n\r\n"
		resp := publishFA(t, s, raw)
		if !strings.HasPrefix(resp, "SIP/2.0 489") {
			t.Fatalf("event %q: response = %q, want 489 Bad Event", event, firstLine(resp))
		}
		if !strings.Contains(resp, "Allow-Events:") {
			t.Fatalf("489 lacks Allow-Events:\n%s", resp)
		}
	}
}

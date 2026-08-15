package sip

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

func TestParseMultipartMCPTTInfo(t *testing.T) {
	raw := "PUBLISH sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=1\r\n" +
		"To: <sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: pub-1\r\n" +
		"CSeq: 1 PUBLISH\r\n" +
		"Event: poc-settings\r\n" +
		"Content-Type: multipart/mixed;boundary=abc\r\n" +
		"Content-Length: 283\r\n\r\n" +
		"--abc\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" +
		"<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><mcptt-Params><mcptt-client-id type=\"Normal\"><mcpttString>sip:16752012881@ims.mnc01.mcc001.3gppnetwork.org</mcpttString></mcptt-client-id></mcptt-Params></mcpttinfo>\r\n" +
		"--abc--\r\n"

	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(msg.Parts()); got != 1 {
		t.Fatalf("parts = %d, want 1", got)
	}
	if got := mcpttIdentityFromBody(msg); got != "sip:16752012881@ims.mnc01.mcc001.3gppnetwork.org" {
		t.Fatalf("mcptt identity = %q", got)
	}
}

func TestMCPTTIdentityPrefersRequestURIOverAccessToken(t *testing.T) {
	raw := "SUBSCRIBE sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=1\r\n" +
		"To: <sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: sub-1\r\n" +
		"CSeq: 1 SUBSCRIBE\r\n" +
		"Event: xcap-diff\r\n" +
		"Content-Type: multipart/mixed;boundary=abc\r\n" +
		"Content-Length: 602\r\n\r\n" +
		"--abc\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" +
		"<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><mcptt-Params>" +
		"<mcptt-access-token type=\"Normal\"><mcpttString>eyJhbGciOiJub25lIn0.eyJzdWIiOiJzaXA6MzExNDM1MzAwMDcwNTgxQGltcy5leGFtcGxlIn0.</mcpttString></mcptt-access-token>" +
		"<mcptt-client-id type=\"Normal\"><mcpttString>sip:16752012881@ims.mnc01.mcc001.3gppnetwork.org</mcpttString></mcptt-client-id>" +
		"<mcptt-request-uri type=\"Normal\"><mcpttURI>sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org</mcpttURI></mcptt-request-uri>" +
		"</mcptt-Params></mcpttinfo>\r\n" +
		"--abc--\r\n"

	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := mcpttIdentityFromBody(msg); got != "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org" {
		t.Fatalf("mcptt identity = %q", got)
	}
}

func TestReadSIPMessageFromTCPStream(t *testing.T) {
	stream := "OPTIONS sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"Call-ID: one\r\nContent-Length: 0\r\n\r\n" +
		"OPTIONS sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"Call-ID: two\r\nContent-Length: 4\r\n\r\ntest"
	r := bufio.NewReader(strings.NewReader(stream))

	first, err := readSIPMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header("Call-ID"); got != "one" {
		t.Fatalf("first Call-ID = %q", got)
	}

	second, err := readSIPMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	msg, err = Parse(second)
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header("Call-ID"); got != "two" {
		t.Fatalf("second Call-ID = %q", got)
	}
	if got := string(msg.Body); got != "test" {
		t.Fatalf("second body = %q", got)
	}
}

func TestPresenceBodyMatchesMCOPShape(t *testing.T) {
	s := &Server{}
	mcpttID := "sip:16752012881@ims.mnc01.mcc001.3gppnetwork.org"
	body := s.presenceBody(mcpttID, "sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org", testTime())

	for _, want := range []string{
		`<presence xmlns="urn:ietf:params:xml:ns:pidf"`,
		`xmlns:mcpttPI10="urn:3gpp:ns:mcpttPresInfo:1.0"`,
		`entity="sip:16752012881@ims.mnc01.mcc001.3gppnetwork.org"`,
		`<tuple id="sip:16752012881@ims.mnc01.mcc001.3gppnetwork.org">`,
		`<contact priority="1.0">sip:16752012881@ims.mnc01.mcc001.3gppnetwork.org</contact>`,
		`<mcpttPI10:affiliation group="sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org" status="affiliated"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("presence body missing %q:\n%s", want, body)
		}
	}
}

func TestPresenceNotifyMembershipImpliesAffiliationUnlessOverridden(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	user, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:u@example.test", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	overriddenGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:overridden@example.test", DisplayName: "Overridden Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defaultGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:default@example.test", DisplayName: "Default Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	nonMemberGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:non-member@example.test", DisplayName: "Non Member Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: overriddenGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: defaultGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}
	// An explicit group_affiliations row overrides the membership-implied default.
	if _, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{UserID: user.ID, GroupID: overriddenGroup.ID, State: "deaffiliated", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	body, contentType := s.notifyBody(ctx, store.Subscription{Event: "presence", SubscriberURI: "sip:u@example.test"})
	text := string(body)
	if contentType != "application/pidf+xml" {
		t.Fatalf("content-type = %q, want application/pidf+xml", contentType)
	}
	for _, want := range []string{
		`<mcpttPI10:affiliation group="sip:overridden@example.test" status="noaffiliated"`,
		`display-name="Overridden Group"`,
		`<mcpttPI10:affiliation group="sip:default@example.test" status="affiliated"`,
		`display-name="Default Group"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("presence NOTIFY missing %q:\n%s", want, text)
		}
	}
	for _, blocked := range []string{
		`status="deaffiliated"`,
		nonMemberGroup.URI,
		`display-name="Non Member Group"`,
	} {
		if strings.Contains(text, blocked) {
			t.Fatalf("presence NOTIFY should not publish unsupported status %q:\n%s", blocked, text)
		}
	}
	if strings.Count(text, `<mcpttPI10:affiliation `) != 2 {
		t.Fatalf("expected one overridden and one membership-implied affiliation entry:\n%s", text)
	}
}

func TestPresenceNotifyMapsDeaffiliatedStateToNoAffiliated(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	user, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:u@example.test", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:group@example.test", DisplayName: "Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: group.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{UserID: user.ID, GroupID: group.ID, State: "deaffiliated", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	body, _ := s.notifyBody(ctx, store.Subscription{Event: "presence", SubscriberURI: "sip:u@example.test"})
	text := string(body)
	if !strings.Contains(text, `status="noaffiliated"`) {
		t.Fatalf("deaffiliated internal state should map to noaffiliated:\n%s", text)
	}
	if strings.Contains(text, `status="deaffiliated"`) {
		t.Fatalf("presence NOTIFY must never emit deaffiliated:\n%s", text)
	}
}

func TestMembershipImpliesAffiliationForAllGroupsIgnoresGMSDocumentSubscribe(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	user, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:u@example.test", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	firstGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:first@example.test", DisplayName: "First", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:other@example.test", DisplayName: "Other", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: firstGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: otherGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	body, _ := s.notifyBody(ctx, store.Subscription{Event: "presence", SubscriberURI: "sip:u@example.test"})
	text := string(body)
	for _, want := range []string{
		`group="sip:first@example.test" status="affiliated"`,
		`group="sip:other@example.test" status="affiliated"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("membership-implied affiliation NOTIFY missing %q:\n%s", want, text)
		}
	}

	_ = s.xcapDiffBody(ctx, "sip:u@example.test", []string{"org.openmobilealliance.groups/global/byGroup/sip:other@example.test"})
	body, _ = s.notifyBody(ctx, store.Subscription{Event: "presence", SubscriberURI: "sip:u@example.test"})
	text = string(body)
	for _, want := range []string{
		`group="sip:first@example.test" status="affiliated"`,
		`group="sip:other@example.test" status="affiliated"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("GMS document subscription changed affiliation, missing %q:\n%s", want, text)
		}
	}
}

func TestXCAPDiffBodyListsMCOPStartupDocuments(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	user, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org", DisplayName: "DEMO Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: group.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.CMS.XCAPRoot = "http://192.0.2.11:8100/xcap-root"
	s := NewServer(cfg, st)
	body := s.xcapDiffBody(ctx, "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org", nil)

	for _, want := range []string{
		`<xcap-diff xmlns="urn:ietf:params:xml:ns:xcap-diff"`,
		`xcap-root="http://192.0.2.11:8100/xcap-root"`,
		`sel="org.3gpp.mcptt.ue-config/users/mcptt_UE_id/mcptt_UE_id"`,
		`sel="org.3gpp.mcptt.user-profile/users/sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org/mcptt-user-profile"`,
		`sel="org.3gpp.mcptt.service-config/global/service-config.xml"`,
		`sel="org.openmobilealliance.groups/global/byGroup/sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("xcap-diff missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "vectorcore-") {
		t.Fatalf("xcap-diff must not use synthetic etags:\n%s", body)
	}
	if strings.Contains(body, `new-etag="&#34;`) || strings.Contains(body, `new-etag="&quot;`) {
		t.Fatalf("xcap-diff should use plain content etags, not XML-escaped quoted etags:\n%s", body)
	}
	if strings.Count(body, `new-etag="`) != 4 {
		t.Fatalf("xcap-diff should include one content etag per concrete document:\n%s", body)
	}
	for _, bad := range []string{
		`sel="org.3gpp.mcptt.ue-config/users/mcptt_UE_id/"`,
		`sel="org.3gpp.mcptt.user-profile/users/sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org/"`,
	} {
		if strings.Contains(body, bad) {
			t.Fatalf("xcap-diff included directory selector %q:\n%s", bad, body)
		}
	}
	if body != s.xcapDiffBody(ctx, "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org", nil) {
		t.Fatalf("xcap-diff etags should be stable for unchanged content:\n%s", body)
	}
}

func TestXcapDiffBodyUsesRequestedSelectors(t *testing.T) {
	cfg := config.Default()
	cfg.CMS.XCAPRoot = "http://192.0.2.11:8100/xcap-root"
	s := NewServer(cfg, nil)
	body := s.xcapDiffBody(context.Background(), "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org", []string{
		"org.3gpp.mcptt.ue-config/users/mcptt_UE_id/",
		"/org.3gpp.mcptt.user-profile/users/sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org/",
		"org.3gpp.mcptt.service-config/global/service-config.xml",
		"org.3gpp.mcptt.service-config/global/service-config.xml",
	})

	for _, want := range []string{
		`sel="org.3gpp.mcptt.ue-config/users/mcptt_UE_id/mcptt_UE_id"`,
		`sel="org.3gpp.mcptt.user-profile/users/sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org/mcptt-user-profile"`,
		`sel="org.3gpp.mcptt.service-config/global/service-config.xml"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("xcap-diff missing requested selector %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "vectorcore-") {
		t.Fatalf("xcap-diff must not use synthetic etags:\n%s", body)
	}
	if strings.Contains(body, `new-etag="&#34;`) || strings.Contains(body, `new-etag="&quot;`) {
		t.Fatalf("xcap-diff should use plain content etags, not XML-escaped quoted etags:\n%s", body)
	}
	if strings.Count(body, `new-etag="`) != 3 {
		t.Fatalf("xcap-diff should include one content etag per requested selector:\n%s", body)
	}
	if strings.Count(body, `org.3gpp.mcptt.service-config/global/service-config.xml`) != 1 {
		t.Fatalf("xcap-diff did not deduplicate requested selector:\n%s", body)
	}
	if strings.Contains(body, `org.openmobilealliance.groups/global/byGroup`) {
		t.Fatalf("xcap-diff included fallback GMS selector despite explicit request:\n%s", body)
	}
}

// The dialog is created by an inbound SUBSCRIBE, so the AS is the UAS and the
// route set is the Record-Route list taken in order (RFC 3261 §12.1.1); the
// in-dialog NOTIFY reuses it unchanged. That gives the IMS terminating path
// AS → S-CSCF → P-CSCF → UE, which is why "preserve" is the default.
func TestNotifyDialogRoutesPreserveRecordRouteSetByDefault(t *testing.T) {
	cfg := config.Default()
	s := NewServer(cfg, nil)

	routes := []string{
		"<sip:mo@192.0.2.52;r2=on;lr=on;ftag=abc>",
		"<sip:mo@192.0.2.52;transport=tcp;r2=on;lr=on;ftag=abc>",
		"<sip:mo@192.0.2.50;lr=on;ftag=abc>",
	}
	got := s.notifyDialogRoutes(routes)
	if strings.Join(got, "\n") != strings.Join(routes, "\n") {
		t.Fatalf("notify routes = %#v, want preserved %#v", got, routes)
	}
}

// "reverse" stays available as an override for non-standard deployments.
func TestNotifyDialogRoutesCanReverseRecordRouteSet(t *testing.T) {
	cfg := config.Default()
	cfg.SIP.NotifyRouteSetOrder = "reverse"
	s := NewServer(cfg, nil)

	got := s.notifyDialogRoutes([]string{
		"<sip:mo@192.0.2.52;r2=on;lr=on;ftag=abc>",
		"<sip:mo@192.0.2.52;transport=tcp;r2=on;lr=on;ftag=abc>",
		"<sip:mo@192.0.2.50;lr=on;ftag=abc>",
	})
	want := []string{
		"<sip:mo@192.0.2.50;lr=on;ftag=abc>",
		"<sip:mo@192.0.2.52;transport=tcp;r2=on;lr=on;ftag=abc>",
		"<sip:mo@192.0.2.52;r2=on;lr=on;ftag=abc>",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("notify routes = %#v, want reversed %#v", got, want)
	}
}

func TestXcapResourceListSelectorsFromMultipartSubscribe(t *testing.T) {
	raw := "SUBSCRIBE sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=1\r\n" +
		"To: <sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: sub-1\r\n" +
		"CSeq: 1 SUBSCRIBE\r\n" +
		"Event: xcap-diff\r\n" +
		"Content-Type: multipart/mixed;boundary=abc\r\n\r\n" +
		"--abc\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" +
		"<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>\r\n" +
		"--abc\r\nContent-Type: application/resource-lists+xml\r\n\r\n" +
		"<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\">" +
		"<list>" +
		"<entry uri=\"org.3gpp.mcptt.ue-config/users/mcptt_UE_id/\"/>" +
		"<entry uri=\"org.3gpp.mcptt.user-profile/users/sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org/\"/>" +
		"<entry uri=\"org.3gpp.mcptt.service-config/global/service-config.xml\"/>" +
		"</list>" +
		"</resource-lists>\r\n" +
		"--abc--\r\n"

	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := xcapResourceListSelectors(msg)
	want := []string{
		"org.3gpp.mcptt.ue-config/users/mcptt_UE_id/mcptt_UE_id",
		"org.3gpp.mcptt.user-profile/users/sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org/mcptt-user-profile",
		"org.3gpp.mcptt.service-config/global/service-config.xml",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("selectors = %#v, want %#v", got, want)
	}
}

func TestNotifyRequestURIUsesRemoteTargetWhenRouted(t *testing.T) {
	sub := store.Subscription{
		SubscriberURI: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
		RemoteTarget:  "sip:001010000000001@198.51.100.116:45911;transport=udp",
	}

	got := notifyRequestURI(sub, []string{"<sip:orig@scscf.ims.mnc01.mcc001.3gppnetwork.org:5060;lr>"}, "ims.mnc01.mcc001.3gppnetwork.org")
	want := sub.RemoteTarget
	if got != want {
		t.Fatalf("notify request-uri = %q, want %q", got, want)
	}
}

func TestNotifyRequestURIFallsBackToRemoteTargetWithoutRoutes(t *testing.T) {
	sub := store.Subscription{
		SubscriberURI: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
		RemoteTarget:  "sip:001010000000001@198.51.100.116:45911;transport=udp",
	}

	got := notifyRequestURI(sub, nil, "ims.mnc01.mcc001.3gppnetwork.org")
	if got != sub.RemoteTarget {
		t.Fatalf("notify request-uri = %q, want %q", got, sub.RemoteTarget)
	}
}

func TestResponsePreservesRepeatedVia(t *testing.T) {
	msg, err := Parse([]byte("OPTIONS sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 192.0.2.50;branch=z9hG4bK1\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK2\r\n" +
		"From: <sip:a@example.test>;tag=a\r\n" +
		"To: <sip:b@example.test>\r\n" +
		"Call-ID: vias\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Content-Length: 0\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	s := &Server{}
	s.respond(func(resp []byte) error {
		out = append([]byte(nil), resp...)
		return nil
	}, msg, 200, "OK", nil, nil)
	text := string(out)
	if strings.Count(text, "\r\nVia: ") != 2 {
		t.Fatalf("response did not preserve both Via headers:\n%s", text)
	}
}

func TestPublishResponseUsesUnquotedSIPETag(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	s := NewServer(config.Default(), st)
	raw := "PUBLISH sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.116:40506;branch=z9hG4bKpub\r\n" +
		"From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=pub\r\n" +
		"To: <sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: pub-etag\r\n" +
		"CSeq: 1 PUBLISH\r\n" +
		"Event: poc-settings\r\n" +
		"Content-Type: application/poc-settings+xml\r\n" +
		"Content-Length: 0\r\n\r\n"
	var resp []byte
	s.handleRaw(t.Context(), "198.51.100.116:40506", "udp", []byte(raw), func(b []byte) error {
		resp = append([]byte(nil), b...)
		return nil
	})
	text := string(resp)
	if !strings.Contains(text, "SIP/2.0 200 OK") {
		t.Fatalf("PUBLISH response was not 200 OK:\n%s", text)
	}
	if strings.Contains(text, "SIP-ETag: \"") {
		t.Fatalf("SIP-ETag must be an unquoted token for MCOP:\n%s", text)
	}
	if !strings.Contains(text, "\r\nSIP-ETag: vc-") {
		t.Fatalf("PUBLISH response missing VectorCore SIP-ETag token:\n%s", text)
	}
}

func TestThirdPartyRegisterCreatesRegistration(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Default()
	cfg.SIP.RecordRoute = true
	cfg.SIP.AdvertiseHost = "192.0.2.11"
	cfg.SIP.AdvertisePort = 5060
	s := NewServer(cfg, st)
	raw := "REGISTER sip:mcptt-as.ims.mnc01.mcc001.3gppnetwork.org:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKreg\r\n" +
		"From: <sip:scscf.ims.mnc01.mcc001.3gppnetwork.org>;tag=scscf\r\n" +
		"To: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: reg-1\r\n" +
		"CSeq: 10 REGISTER\r\n" +
		"Contact: <sip:001010000000001@198.51.100.116:37457;transport=udp>;expires=1700;audio;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\";+g.3gpp.mcptt\r\n" +
		"Content-Length: 0\r\n\r\n"
	var resp []byte
	s.handleRaw(t.Context(), "192.0.2.52:5060", "udp", []byte(raw), func(b []byte) error {
		resp = append([]byte(nil), b...)
		return nil
	})
	if !strings.Contains(string(resp), "SIP/2.0 200 OK") {
		t.Fatalf("response = %s", resp)
	}
	reg, err := st.GetRegistration(t.Context(), "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org")
	if err != nil {
		t.Fatal(err)
	}
	if reg == nil || !reg.Registered || reg.State != "registered" || reg.ExpiresSeconds != 1700 {
		t.Fatalf("registration = %#v", reg)
	}
	if len(reg.ICSIRefs) != 1 || reg.ICSIRefs[0] != "urn:urn-7:3gpp-service.ims.icsi.mcptt" {
		t.Fatalf("icsi_refs = %#v", reg.ICSIRefs)
	}
}

func TestThirdPartyRegisterEventWithoutFeatureTagCreatesRegistration(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewServer(config.Default(), st)
	raw := "REGISTER sip:mcptt-as.ims.mnc01.mcc001.3gppnetwork.org:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKreg\r\n" +
		"From: <sip:scscf.ims.mnc01.mcc001.3gppnetwork.org>;tag=scscf\r\n" +
		"To: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: reg-event-1\r\n" +
		"CSeq: 10 REGISTER\r\n" +
		"Event: registration\r\n" +
		"Contact: <sip:scscf.ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Content-Length: 0\r\n\r\n"
	s.handleRaw(t.Context(), "192.0.2.52:5060", "udp", []byte(raw), func([]byte) error { return nil })
	reg, err := st.GetRegistration(t.Context(), "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org")
	if err != nil {
		t.Fatal(err)
	}
	if reg == nil || !reg.Registered || reg.State != "registered" {
		t.Fatalf("registration = %#v", reg)
	}
}

func TestThirdPartyUnregisterExpiresRegistration(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewServer(config.Default(), st)
	raw := "REGISTER sip:mcptt-as.ims.mnc01.mcc001.3gppnetwork.org:5060 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKunreg\r\n" +
		"From: <sip:scscf.ims.mnc01.mcc001.3gppnetwork.org>;tag=scscf\r\n" +
		"To: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: unreg-1\r\n" +
		"CSeq: 11 REGISTER\r\n" +
		"Contact: *\r\n" +
		"Expires: 0\r\n" +
		"Content-Length: 0\r\n\r\n"
	s.handleRaw(t.Context(), "192.0.2.52:5060", "udp", []byte(raw), func([]byte) error { return nil })
	reg, err := st.GetRegistration(t.Context(), "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org")
	if err != nil {
		t.Fatal(err)
	}
	if reg == nil || reg.Registered || reg.State != "unregistered" || reg.LastUnregisteredAt.IsZero() {
		t.Fatalf("registration = %#v", reg)
	}
}

func TestInviteLifecycleTracksCallState(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Default()
	cfg.SIP.AdvertiseHost = "192.0.2.11"
	cfg.Media.AdvertiseHost = "192.0.2.11"
	s := NewServer(cfg, st)
	rawInvite := "INVITE sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKinvite\r\n" +
		"From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=from1\r\n" +
		"To: <sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: invite-1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:001010000000001@198.51.100.116:38897;transport=udp>\r\n" +
		"Content-Type: application/sdp\r\n\r\n" +
		"v=0\r\n" +
		"o=ue 0 0 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0 8 96\r\n" +
		"a=sendrecv\r\n" +
		"m=application 49172 UDP/MCPTT 100\r\n" +
		"a=floorctrl:c-s\r\n" +
		"a=fmtp:100 MCPTT mc_priority=7;mc_granted;mc_implicit_request\r\n" +
		"a=setup:active\r\n"
	var inviteResponses []string
	s.handleRaw(t.Context(), "192.0.2.52:5060", "udp", []byte(rawInvite), func(b []byte) error {
		inviteResponses = append(inviteResponses, string(b))
		return nil
	})
	if len(inviteResponses) != 3 {
		t.Fatalf("responses = %d, want 3", len(inviteResponses))
	}
	if !strings.Contains(inviteResponses[2], "Contact: <sip:mcptt-session-") || !strings.Contains(inviteResponses[2], ";isfocus") {
		t.Fatalf("200 OK missing MCPTT session identity Contact with isfocus:\n%s", inviteResponses[2])
	}
	if !strings.Contains(inviteResponses[2], "Record-Route: <sip:192.0.2.11:5060;transport=udp;lr>") {
		t.Fatalf("200 OK missing Record-Route:\n%s", inviteResponses[2])
	}
	okMsg, err := Parse([]byte(inviteResponses[2]))
	if err != nil {
		t.Fatal(err)
	}
	localTag := tagFrom(okMsg.Header("To"))
	if localTag == "" {
		t.Fatalf("200 OK missing To tag:\n%s", inviteResponses[2])
	}
	call, err := st.GetCall(t.Context(), "invite-1")
	if err != nil {
		t.Fatal(err)
	}
	if call == nil || call.State != "answered" || call.InitiatorURI != "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org" || call.RemoteTarget == "" || call.SDPOffer == "" || call.SDPAnswer == "" {
		t.Fatalf("call after INVITE = %#v", call)
	}
	if call.AudioIP != "198.51.100.116" || call.AudioPort != 49170 || call.AudioProto != "RTP/AVP" || len(call.AudioPayloads) != 3 {
		t.Fatalf("audio media = %#v", call)
	}
	if call.FloorControlIP != "198.51.100.116" || call.FloorControlPort != 49172 || call.FloorControlProto != "UDP/MCPTT" || len(call.FloorControlAttrs) != 3 {
		t.Fatalf("floor control media = %#v", call)
	}
	if call.FloorState != "granted" || call.FloorLastEvent != "sdp_granted" {
		t.Fatalf("floor state = %#v", call)
	}
	if call.LocalAudioPort != 40000 || call.LocalRTCPPort != 40001 || call.LocalFloorPort != 40002 {
		t.Fatalf("local media ports = %#v", call)
	}

	rawACK := "ACK sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKack\r\n" +
		"From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=from1\r\n" +
		"To: <sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org>;tag=" + localTag + "\r\n" +
		"Call-ID: invite-1\r\n" +
		"CSeq: 1 ACK\r\n" +
		"Content-Length: 0\r\n\r\n"
	s.handleRaw(t.Context(), "192.0.2.52:5060", "udp", []byte(rawACK), func([]byte) error { return nil })
	call, err = st.GetCall(t.Context(), "invite-1")
	if err != nil {
		t.Fatal(err)
	}
	if call == nil || call.State != "established" || call.EstablishedAt.IsZero() {
		t.Fatalf("call after ACK = %#v", call)
	}

	rawBYE := "BYE sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKbye\r\n" +
		"From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=from1\r\n" +
		"To: <sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org>;tag=" + localTag + "\r\n" +
		"Call-ID: invite-1\r\n" +
		"CSeq: 2 BYE\r\n" +
		"Content-Length: 0\r\n\r\n"
	var byeResp []byte
	s.handleRaw(t.Context(), "192.0.2.52:5060", "udp", []byte(rawBYE), func(b []byte) error {
		byeResp = append([]byte(nil), b...)
		return nil
	})
	if !strings.Contains(string(byeResp), "SIP/2.0 200 OK") {
		t.Fatalf("BYE response = %s", byeResp)
	}
	call, err = st.GetCall(t.Context(), "invite-1")
	if err != nil {
		t.Fatal(err)
	}
	if call == nil || call.State != "terminated" || call.TerminatedAt.IsZero() {
		t.Fatalf("call after BYE = %#v", call)
	}
}

func TestGroupInviteRequiresMembership(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := t.Context()
	user, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:u@example.test", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	memberGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:member_group@example.test", DisplayName: "Member Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	nonMemberGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:other_group@example.test", DisplayName: "Other Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: memberGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{UserID: user.ID, GroupID: memberGroup.ID, State: "affiliated"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	var rejected []string
	s.handleRaw(ctx, "192.0.2.52:5060", "udp", []byte(groupInvite("group-reject", "sip:u@example.test", nonMemberGroup.URI)), func(b []byte) error {
		rejected = append(rejected, string(b))
		return nil
	})
	if len(rejected) != 1 || !strings.Contains(rejected[0], "SIP/2.0 403 Forbidden") {
		t.Fatalf("reject responses = %#v", rejected)
	}
	if !strings.Contains(rejected[0], `"120 user is not affiliated to this group"`) {
		t.Fatalf("rejection lacks the clause 4.4.2 warning text:\n%s", rejected[0])
	}
	call, err := st.GetCall(ctx, "group-reject")
	if err != nil {
		t.Fatal(err)
	}
	if call != nil {
		t.Fatalf("rejected group INVITE should not create call: %#v", call)
	}

	var accepted []string
	s.handleRaw(ctx, "192.0.2.52:5060", "udp", []byte(groupInvite("group-accept", "sip:u@example.test", memberGroup.URI)), func(b []byte) error {
		accepted = append(accepted, string(b))
		return nil
	})
	if len(accepted) != 3 || !strings.Contains(accepted[2], "SIP/2.0 200 OK") {
		t.Fatalf("accept responses = %#v", accepted)
	}
	call, err = st.GetCall(ctx, "group-accept")
	if err != nil {
		t.Fatal(err)
	}
	if call == nil || call.GroupURI != memberGroup.URI || call.InitiatorURI != "sip:u@example.test" {
		t.Fatalf("accepted group call = %#v", call)
	}
}

func groupInvite(callID, fromURI, targetURI string) string {
	return "INVITE " + targetURI + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"From: <" + fromURI + ">;tag=from1\r\n" +
		"To: <" + targetURI + ">\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <" + fromURI + "@198.51.100.116:38897;transport=udp>\r\n" +
		"Content-Type: application/sdp\r\n\r\n" +
		"v=0\r\n" +
		"o=ue 0 0 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"a=sendrecv\r\n" +
		"m=application 49172 UDP/MCPTT 100\r\n" +
		"a=fmtp:100 MCPTT mc_priority=7;mc_granted;mc_implicit_request\r\n"
}

func TestSDPAnswerPreservesMCPTTFloorFormat(t *testing.T) {
	cfg := config.Default()
	cfg.Media.AdvertiseHost = "192.0.2.54"
	cfg.Media.AudioPort = 41000
	cfg.Media.RTCPPort = 41001
	cfg.Media.FloorControlPort = 41002
	s := NewServer(cfg, nil)
	msg, err := Parse([]byte("INVITE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Content-Type: application/sdp\r\n\r\n" +
		"v=0\r\n" +
		"o=ue 0 0 IN IP4 192.0.2.10\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 42576 RTP/AVP 0 8 96\r\n" +
		"m=application 22914 udp MCPTT\r\n" +
		"a=fmtp:MCPTT MCPTT mc_priority=7;mc_granted;mc_implicit_request\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	body, ct := s.sdpAnswer(msg)
	if ct != "application/sdp" {
		t.Fatalf("content type = %q", ct)
	}
	text := string(body)
	for _, want := range []string{
		"m=audio 41000 RTP/AVP 0\r\n",
		"m=application 41002 udp MCPTT\r\n",
		"a=fmtp:MCPTT MCPTT mc_priority=0;mc_granted;mc_implicit_request\r\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SDP answer missing %q:\n%s", want, text)
		}
	}
}

func TestUnknownBYEReturns481(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewServer(config.Default(), st)
	rawBYE := "BYE sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKunknownbye\r\n" +
		"From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=from1\r\n" +
		"To: <sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org>;tag=to1\r\n" +
		"Call-ID: unknown-bye\r\n" +
		"CSeq: 2 BYE\r\n" +
		"Content-Length: 0\r\n\r\n"
	var resp []byte
	s.handleRaw(t.Context(), "192.0.2.52:5060", "udp", []byte(rawBYE), func(b []byte) error {
		resp = append([]byte(nil), b...)
		return nil
	})
	if !strings.Contains(string(resp), "SIP/2.0 481 Call/Transaction Does Not Exist") {
		t.Fatalf("response = %s", resp)
	}
}

func TestParseSDPFloorControl(t *testing.T) {
	info := parseSDP("v=0\r\n" +
		"o=ue 0 0 IN IP4 192.0.2.20\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 192.0.2.20\r\n" +
		"t=0 0\r\n" +
		"m=audio 4000 RTP/AVP 0\r\n" +
		"a=sendrecv\r\n" +
		"m=application 4002 UDP/MCPTT 98\r\n" +
		"a=floorctrl:c-s\r\n")
	if info.Audio.ConnectionIP != "192.0.2.20" || info.Audio.Port != 4000 || info.Audio.Proto != "RTP/AVP" {
		t.Fatalf("audio = %#v", info.Audio)
	}
	if info.FloorControl.ConnectionIP != "192.0.2.20" || info.FloorControl.Port != 4002 || info.FloorControl.Proto != "UDP/MCPTT" {
		t.Fatalf("floor = %#v", info.FloorControl)
	}
}

func TestMediaEndpoint(t *testing.T) {
	if got := mediaEndpoint("198.51.100.116", 13400); got != "198.51.100.116:13400" {
		t.Fatalf("mediaEndpoint = %q", got)
	}
	if got := mediaEndpoint("", 13400); got != "" {
		t.Fatalf("empty host mediaEndpoint = %q", got)
	}
	if got := mediaEndpoint("198.51.100.116", 0); got != "" {
		t.Fatalf("zero port mediaEndpoint = %q", got)
	}
}

func TestSDPAnswerUsesMediaConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Media.AdvertiseHost = "192.0.2.54"
	cfg.Media.Direction = "sendrecv"
	cfg.Media.AudioPort = 41000
	cfg.Media.RTCPPort = 41001
	cfg.Media.FloorControlPort = 41002
	s := NewServer(cfg, nil)
	msg, err := Parse([]byte("INVITE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 5\r\n\r\n" +
		"v=0\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	body, ct := s.sdpAnswer(msg)
	if ct != "application/sdp" {
		t.Fatalf("content type = %q", ct)
	}
	text := string(body)
	for _, want := range []string{
		"c=IN IP4 192.0.2.54\r\n",
		"m=audio 41000 RTP/AVP 0\r\n",
		"a=rtcp:41001 IN IP4 192.0.2.54\r\n",
		"a=sendrecv\r\n",
		"m=application 41002 udp MCPTT\r\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SDP answer missing %q:\n%s", want, text)
		}
	}
	// The offer requested no implicit floor, so the answer must not grant one
	// (TS 24.380 clause 6.4).
	if strings.Contains(text, "mc_granted") {
		t.Fatalf("SDP answer granted the floor to an offer that did not request it:\n%s", text)
	}
	if !strings.Contains(text, "mc_queueing") {
		t.Fatalf("SDP answer without an implicit grant should advertise mc_queueing:\n%s", text)
	}
}

// An offer that requests an implicit floor grant is granted when auto-grant is
// on, and withheld when auto-grant is off (TS 24.380 clause 6.4).
func TestSDPAnswerGrantsFloorOnlyWhenRequestedAndAllowed(t *testing.T) {
	offer := "INVITE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Content-Type: application/sdp\r\n\r\n" +
		"v=0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=application 49172 udp MCPTT\r\n" +
		"a=fmtp:MCPTT mc_implicit_request\r\n"
	msg, err := Parse([]byte(offer))
	if err != nil {
		t.Fatal(err)
	}

	granting := config.Default()
	granting.Media.FloorAutoGrant = true
	if body, _ := NewServer(granting, nil).sdpAnswer(msg); !strings.Contains(string(body), "mc_granted") {
		t.Fatalf("an implicit-request offer with auto-grant on must be granted:\n%s", body)
	}

	withheld := config.Default()
	withheld.Media.FloorAutoGrant = false
	if body, _ := NewServer(withheld, nil).sdpAnswer(msg); strings.Contains(string(body), "mc_granted") {
		t.Fatalf("auto-grant off must not grant the floor:\n%s", body)
	}
}

func testTime() time.Time {
	return time.Unix(1780160000, 0).UTC()
}

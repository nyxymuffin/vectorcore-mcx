package cms

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

func TestRequestedUserProfileUsesRequestedUserMembershipsNotAffiliations(t *testing.T) {
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
	memberGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:member@example.test", DisplayName: "Member", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:other@example.test", DisplayName: "Other", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: memberGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: otherGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}
	firstUser, err := st.CreateUser(ctx, store.User{IMPI: "first@example.test", IMPU: "sip:first@example.test", MCPTTID: "sip:mcptt-first@example.test", DisplayName: "First", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	firstGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:first-group@example.test", DisplayName: "First Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: firstUser.ID, GroupID: firstGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	body := s.defaultUserProfile(ctx, "/org.3gpp.mcptt.user-profile/users/sip:u@example.test/mcptt-user-profile.xml")
	if !strings.Contains(body, "sip:member@example.test") || !strings.Contains(body, "sip:other@example.test") {
		t.Fatalf("profile should contain membership groups:\n%s", body)
	}
	if strings.Contains(body, "sip:first-group@example.test") {
		t.Fatalf("profile must use requested user, not first enabled user:\n%s", body)
	}

	affiliation, err := st.CreateGroupAffiliation(ctx, store.GroupAffiliation{UserID: user.ID, GroupID: memberGroup.ID, State: "affiliated"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateGroupAffiliation(ctx, affiliation.ID, store.GroupAffiliation{UserID: user.ID, GroupID: memberGroup.ID, State: "deaffiliated"}); err != nil {
		t.Fatal(err)
	}
	body = s.defaultUserProfile(ctx, "/org.3gpp.mcptt.user-profile/users/sip:u@example.test/mcptt-user-profile.xml")
	if !strings.Contains(body, "sip:member@example.test") || !strings.Contains(body, "sip:other@example.test") {
		t.Fatalf("runtime affiliation must not remove membership groups:\n%s", body)
	}
}

func TestGeneratedCMSAndGMSDocumentsMeetRel13Envelope(t *testing.T) {
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

	cfg := config.Default()
	cfg.IMS.MCC = "001"
	cfg.IMS.MNC = "01"
	cfg.IMS.Realm = "ims.example.test"
	cfg.MCX.CMSURI = "sip:cms@ims.example.test"
	cfg.MCX.GMSURI = "sip:gms@ims.example.test"
	cfg.MCX.KMSURI = "sip:kms@ims.example.test"
	cfg.CMS.XCAPRoot = "http://cms.example.test/xcap-root"
	s := NewServer(cfg, st)

	cases := []struct {
		name        string
		path        string
		root        xml.Name
		contentType string
		want        []string
	}{
		{
			name:        "ue-init",
			path:        "/org.3gpp.mcptt.ue-init-config/users/mcptt_UE_id/mcptt_UE_id",
			root:        xml.Name{Space: "urn:3gpp:mcptt:mcpttUEinitConfig:1.0", Local: "mcptt-UE-initial-configuration"},
			contentType: "application/vnd.3gpp.mcptt-ue-init-config+xml",
			want: []string{
				`XUI-URI="sip:mcptt-user@ims.example.test"`,
				`<mcptt-UE-id index="0">`,
				`<Instance-ID-URN>urn:uuid:00000000-0000-4000-8000-000000000001</Instance-ID-URN>`,
				`<Default-user-profile User-ID="default"`,
				`<GMS-XCAP-root-URI>http://cms.example.test/xcap-root</GMS-XCAP-root-URI>`,
				`<CMS-XCAP-root-URI>http://cms.example.test/xcap-root</CMS-XCAP-root-URI>`,
				`<HPLMN PLMN="00101">`,
				`<VPLMN PLMN="00101">`,
				`<MCPTT-to-con-ref>sip:cms@ims.example.test</MCPTT-to-con-ref>`,
				`<TFG1>1000</TFG1>`,
				`<CFP1>3</CFP1>`,
			},
		},
		{
			name:        "ue-config",
			path:        "/org.3gpp.mcptt.ue-config/users/sip:u@example.test/mcptt_UE_id",
			root:        xml.Name{Space: "urn:3gpp:mcptt:mcpttUEConfig:1.0", Local: "mcptt-UE-configuration"},
			contentType: "application/vnd.3gpp.mcptt-ue-config+xml",
			want: []string{
				`domain="ims.example.test"`,
				`XUI-URI="sip:u@example.test"`,
				`<mcptt-UE-id index="0">`,
				`<Instance-ID-URN>urn:uuid:00000000-0000-4000-8000-000000000001</Instance-ID-URN>`,
				`<Max-Simul-Call-N10>1</Max-Simul-Call-N10>`,
				`<Max-Simul-Call-N4>1</Max-Simul-Call-N4>`,
				`<Max-Simul-Trans-N5>1</Max-Simul-Trans-N5>`,
				`<IPv6Preferred>false</IPv6Preferred>`,
				`<Relay-Service>false</Relay-Service>`,
			},
		},
		{
			name:        "user-profile",
			path:        "/org.3gpp.mcptt.user-profile/users/sip:u@example.test/mcptt-user-profile.xml",
			root:        xml.Name{Space: "urn:3gpp:mcptt:user-profile:1.0", Local: "mcptt-user-profile"},
			contentType: "application/vnd.3gpp.mcptt-user-profile+xml",
			want: []string{
				`<MCPTTUserID entry-info="UsePreConfigured" index="0">`,
				`<UserAlias>`,
				`<alias-entry xml:lang="en" index="0">User</alias-entry>`,
				`<PrivateCall>`,
				`<PrivateCallList index="0">`,
				`<PrivateCallURI entry-info="UsePreConfigured" index="0">`,
				`<MCPTT-group-call>`,
				`<MaxSimultaneousCallsN6>1</MaxSimultaneousCallsN6>`,
				`<MaxSimultaneousTransmissionsN7>1</MaxSimultaneousTransmissionsN7>`,
				`<MCPTTGroupInfo xml:lang="en" index="0">`,
				`sip:group@example.test`,
			},
		},
		{
			name:        "service-config",
			path:        "/org.3gpp.mcptt.service-config/global/service-config.xml",
			root:        xml.Name{Space: "urn:3gpp:ns:mcpttServiceConfig:1.0", Local: "service-configuration-info"},
			contentType: "application/vnd.3gpp.mcptt-service-config+xml",
			want: []string{
				`<service-configuration-params domain="ims.example.test">`,
				`<time-limit>PT300S</time-limit>`,
				`<max-user-request-time>PT30S</max-user-request-time>`,
				`<fc-timers-counters>`,
				`<T1-end-of-rtp-media>PT5S</T1-end-of-rtp-media>`,
				`<C56-disconnect>3</C56-disconnect>`,
				`<emergency-resource-priority>`,
				`<normal-resource-priority>`,
			},
		},
		{
			name:        "gms-group",
			path:        "/org.openmobilealliance.groups/global/byGroup/sip:group@example.test",
			root:        xml.Name{Space: "urn:oma:xml:poc:list-service", Local: "group"},
			contentType: "application/vnd.oma.poc.groups+xml",
			want: []string{
				`xmlns:rl="urn:ietf:params:xml:ns:resource-lists"`,
				`xmlns:cp="urn:ietf:params:xml:ns:common-policy"`,
				`xmlns:mcpttgi="urn:3gpp:ns:mcpttGroupInfo:1.0"`,
				`<list-service uri="sip:group@example.test">`,
				`<entry uri="sip:u@example.test">`,
				`<mcpttgi:on-network-group-priority>1</mcpttgi:on-network-group-priority>`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := s.defaultDocument(ctx, tc.path)
			assertXMLRoot(t, body, tc.root)
			if got := contentTypeForPath(tc.path); got != tc.contentType {
				t.Fatalf("content-type = %q, want %q", got, tc.contentType)
			}
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("document missing %q:\n%s", want, body)
				}
			}
		})
	}
}

func TestGeneratedCMSDocumentsValidateAgainstRel13XSD(t *testing.T) {
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skip("xmllint not installed")
	}
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

	cfg := config.Default()
	cfg.IMS.MCC = "001"
	cfg.IMS.MNC = "01"
	cfg.IMS.Realm = "ims.example.test"
	cfg.MCX.CMSURI = "sip:cms@ims.example.test"
	cfg.MCX.GMSURI = "sip:gms@ims.example.test"
	cfg.MCX.KMSURI = "sip:kms@ims.example.test"
	cfg.MCX.IDMSAuthEndpoint = "http://idms.example.test/authorize"
	cfg.MCX.IDMSTokenEndpoint = "http://idms.example.test/token"
	cfg.MCX.HTTPProxyURI = "http://proxy.example.test"
	cfg.CMS.XCAPRoot = "http://cms.example.test/xcap-root"
	s := NewServer(cfg, st)

	cases := []struct {
		name   string
		path   string
		schema string
	}{
		{
			name:   "ue-init",
			path:   "/org.3gpp.mcptt.ue-init-config/users/mcptt_UE_id/mcptt_UE_id",
			schema: "ue-init-config.xsd",
		},
		{
			name:   "ue-config",
			path:   "/org.3gpp.mcptt.ue-config/users/sip:u@example.test/mcptt_UE_id",
			schema: "ue-config.xsd",
		},
		{
			name:   "user-profile",
			path:   "/org.3gpp.mcptt.user-profile/users/sip:u@example.test/mcptt-user-profile.xml",
			schema: "mcptt-user-profile.xsd",
		},
		{
			name:   "service-config",
			path:   "/org.3gpp.mcptt.service-config/global/service-config.xml",
			schema: "Servconf.xsd",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xmlPath := filepath.Join(t.TempDir(), tc.name+".xml")
			if err := os.WriteFile(xmlPath, []byte(s.defaultDocument(ctx, tc.path)), 0o600); err != nil {
				t.Fatal(err)
			}
			schemaPath := filepath.Join("testdata", "rel13", tc.schema)
			cmd := exec.Command("xmllint", "--noout", "--schema", schemaPath, xmlPath)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("xmllint failed for %s:\n%s", tc.name, out)
			}
		})
	}
}

func TestDefaultUserProfileIsNotUserSpecific(t *testing.T) {
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
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:member@example.test", DisplayName: "Member", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: group.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	body := s.defaultUserProfile(ctx, "/org.3gpp.mcptt.user-profile/users/default/mcptt-user-profile.xml")
	for _, forbidden := range []string{"sip:u@example.test", "sip:mcptt-u@example.test", "sip:member@example.test"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("default profile must not include user-specific value %q:\n%s", forbidden, body)
		}
	}
	if !strings.Contains(body, "VectorCore Default Profile") || !strings.Contains(body, `<MCPTTUserID entry-info="UsePreConfigured" index="0">`) {
		t.Fatalf("default profile missing default user data:\n%s", body)
	}
}

func TestDefaultUEConfigIsGeneratedForMCOPClient(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	firstUser, err := st.CreateUser(ctx, store.User{IMPI: "first@example.test", IMPU: "sip:first@example.test", MCPTTID: "sip:mcptt-first@example.test", DisplayName: "First", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	firstGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:first-group@example.test", DisplayName: "First Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: firstUser.ID, GroupID: firstGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:u@example.test", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	memberGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:member@example.test", DisplayName: "Member", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	nonMemberGroup, err := st.CreateGroup(ctx, store.Group{URI: "sip:nonmember@example.test", DisplayName: "Non-member", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: memberGroup.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	body := s.defaultDocument(ctx, "/org.3gpp.mcptt.ue-config/users/sip:u@example.test/mcptt_UE_id")
	if !strings.Contains(body, "<mcptt-UE-configuration") {
		t.Fatalf("expected MCOP UE config document, got:\n%s", body)
	}
	if strings.Contains(body, "<mcx-document") {
		t.Fatalf("UE config must not use generic fallback:\n%s", body)
	}
	if !strings.Contains(body, `XUI-URI="sip:u@example.test"`) || !strings.Contains(body, `<name xml:lang="en">User</name>`) {
		t.Fatalf("UE config should use requested XUI user identity:\n%s", body)
	}
	if !strings.Contains(body, "sip:member@example.test") {
		t.Fatalf("UE config should include membership group priority:\n%s", body)
	}
	if strings.Contains(body, nonMemberGroup.URI) {
		t.Fatalf("UE config should not include non-membership groups:\n%s", body)
	}
	if strings.Contains(body, firstGroup.URI) {
		t.Fatalf("UE config must use requested user, not first enabled user:\n%s", body)
	}
}

func TestDefaultServiceConfigIsGeneratedForMCOPClient(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := config.Default()
	cfg.IMS.Realm = "ims.example.test"
	s := NewServer(cfg, st)
	body := s.defaultDocument(context.Background(), "/org.3gpp.mcptt.service-config/global/service-config.xml")

	for _, want := range []string{
		`<service-configuration-info xmlns="urn:3gpp:ns:mcpttServiceConfig:1.0">`,
		`<service-configuration-params domain="ims.example.test">`,
		`<common>`,
		`<on-network>`,
		`<transmit-time>`,
		`<floor-control-queue>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("service config missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<mcx-document") {
		t.Fatalf("service config must not use generic fallback:\n%s", body)
	}
}

func TestDefaultUserProfileUsesRel13UserProfileSchemaShape(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := config.Default()
	s := NewServer(cfg, st)
	body := s.defaultDocument(context.Background(), "/org.3gpp.mcptt.user-profile/users/default/mcptt-user-profile.xml")

	for _, forbidden := range []string{
		`<ruleset>`,
		`<MCPTTUserID>`,
		`<UserAlias><entry`,
		`<Authorized>`,
		`<ManualCommencement>`,
		`<MCPTTGroupInitiation>`,
		`<allow-private-call>`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("user profile contains non-Rel-13 shape %q:\n%s", forbidden, body)
		}
	}
	for _, want := range []string{
		`<MCPTTUserID entry-info="UsePreConfigured" index="0">`,
		`<UserAlias>`,
		`<alias-entry xml:lang="en" index="0">`,
		`<PrivateCallList index="0">`,
		`<PrivateCallURI entry-info="UsePreConfigured" index="0">`,
		`<MCPTT-group-call>`,
		`<MaxSimultaneousCallsN6>1</MaxSimultaneousCallsN6>`,
		`<OnNetwork index="0">`,
		`<MaxSimultaneousTransmissionsN7>1</MaxSimultaneousTransmissionsN7>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("user profile missing Rel-13 shape %q:\n%s", want, body)
		}
	}
}

func TestDefaultUEInitConfigAdvertisesGMSXCAPRoot(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	if _, err := st.CreateUser(ctx, store.User{IMPI: "u@example.test", IMPU: "sip:u@example.test", MCPTTID: "sip:mcptt-u@example.test", DisplayName: "User", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CMS.XCAPRoot = "http://192.0.2.11:8100/xcap-root/"
	s := NewServer(cfg, st)

	body := s.defaultDocument(ctx, "/org.3gpp.mcptt.ue-init-config/users/mcptt_UE_id/mcptt_UE_id")
	for _, want := range []string{
		`<mcptt-UE-initial-configuration`,
		`XUI-URI="sip:mcptt-user@ims.example.test"`,
		`<mcptt-UE-id index="0">`,
		`<Instance-ID-URN>urn:uuid:00000000-0000-4000-8000-000000000001</Instance-ID-URN>`,
		`<GMS-XCAP-root-URI>http://192.0.2.11:8100/xcap-root</GMS-XCAP-root-URI>`,
		`<CMS-XCAP-root-URI>http://192.0.2.11:8100/xcap-root</CMS-XCAP-root-URI>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("UE init config missing %q:\n%s", want, body)
		}
	}
}

func TestDefaultGMSGroupDocumentIsGeneratedForMCOPClient(t *testing.T) {
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
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org", DisplayName: "DEMO Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: group.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	body := s.defaultDocument(ctx, "/org.openmobilealliance.groups/global/byGroup/sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org")
	for _, want := range []string{
		`<group xmlns="urn:oma:xml:poc:list-service"`,
		`<list-service uri="sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org">`,
		`<display-name xml:lang="en">DEMO Group</display-name>`,
		`<entry uri="sip:u@example.test">`,
		`<participant-type>MCPTT User</participant-type>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GMS group document missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "%!(EXTRA") {
		t.Fatalf("GMS group document contains fmt error:\n%s", body)
	}
	if strings.Contains(body, "<mcx-document") {
		t.Fatalf("GMS group document must not use generic fallback:\n%s", body)
	}
}

func TestGMSGroupXCAPRequestReturnsGroupDocument(t *testing.T) {
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
	group, err := st.CreateGroup(ctx, store.Group{URI: "sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org", DisplayName: "DEMO Group", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGroupMembership(ctx, store.GroupMembership{UserID: user.ID, GroupID: group.ID, Role: "MCPTT User"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(config.Default(), st)
	req := httptest.NewRequest(http.MethodGet, "/xcap-root/org.openmobilealliance.groups/global/byGroup/sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org", nil)
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if got := rr.Header().Get("Content-Type"); got != "application/vnd.oma.poc.groups+xml" {
		t.Fatalf("content-type = %q, want application/vnd.oma.poc.groups+xml", got)
	}
	if !strings.Contains(body, `<list-service uri="sip:DEMO_group@ims.mnc01.mcc001.3gppnetwork.org">`) {
		t.Fatalf("HTTP GMS response did not contain group document:\n%s", body)
	}
}

func TestXCAPGeneratedDocumentETagIsStableAndStillReturnsBody(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	s := NewServer(config.Default(), st)
	req := httptest.NewRequest(http.MethodGet, "/xcap-root/org.3gpp.mcptt.service-config/global/service-config.xml", nil)
	rr := httptest.NewRecorder()
	s.handleXCAP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	tag := rr.Header().Get("ETag")
	if tag == "" || !strings.HasPrefix(tag, `"`) || !strings.HasSuffix(tag, `"`) {
		t.Fatalf("etag = %q, want quoted content etag", tag)
	}
	body := rr.Body.String()

	// Conditional GET, RFC 4825 clause 7.10: a matching If-None-Match is a
	// 304 without a body (this replaced the pre-conformance behavior of
	// ignoring the header and re-sending the document).
	req = httptest.NewRequest(http.MethodGet, "/xcap-root/org.3gpp.mcptt.service-config/global/service-config.xml", nil)
	req.Header.Set("If-None-Match", tag)
	rr = httptest.NewRecorder()
	s.handleXCAP(rr, req)

	if rr.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304; body:\n%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("ETag"); got != tag {
		t.Fatalf("etag = %q, want %q", got, tag)
	}

	// A stale entity tag still gets the full document.
	req = httptest.NewRequest(http.MethodGet, "/xcap-root/org.3gpp.mcptt.service-config/global/service-config.xml", nil)
	req.Header.Set("If-None-Match", `"different"`)
	rr = httptest.NewRecorder()
	s.handleXCAP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for stale etag", rr.Code)
	}
	if got := rr.Body.String(); got != body {
		t.Fatalf("body changed for unchanged content:\nfirst:\n%s\nsecond:\n%s", body, got)
	}
}

func assertXMLRoot(t *testing.T, body string, want xml.Name) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("invalid XML: %v\n%s", err, body)
		}
		if start, ok := tok.(xml.StartElement); ok {
			if start.Name != want {
				t.Fatalf("root = {%s}%s, want {%s}%s\n%s", start.Name.Space, start.Name.Local, want.Space, want.Local, body)
			}
			return
		}
		if tok == nil {
			t.Fatal(io.EOF)
		}
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigIsNotLabRealmSpecific(t *testing.T) {
	cfg := Default()

	if cfg.IMS.Realm != "ims.example.test" {
		t.Fatalf("realm = %q, want generic default", cfg.IMS.Realm)
	}
	if cfg.SIP.AdvertiseHost != "127.0.0.1" {
		t.Fatalf("sip advertise host = %q, want loopback fallback", cfg.SIP.AdvertiseHost)
	}
	if cfg.CMS.XCAPRoot != "http://127.0.0.1:8100/xcap-root" {
		t.Fatalf("xcap root = %q, want loopback-derived default", cfg.CMS.XCAPRoot)
	}
	if cfg.MCX.DefaultUserIdentity != "sip:mcptt-user@ims.example.test" {
		t.Fatalf("default user identity = %q, want realm-derived identity", cfg.MCX.DefaultUserIdentity)
	}
	if cfg.MCX.DefaultGroupURI != "sip:mcptt-group@ims.example.test" {
		t.Fatalf("default group URI = %q, want realm-derived URI", cfg.MCX.DefaultGroupURI)
	}
	if cfg.MCX.UEXUIURI != "sip:mcptt-user@ims.example.test" {
		t.Fatalf("UE XUI URI = %q, want default user identity", cfg.MCX.UEXUIURI)
	}
	if cfg.MCX.UEInstanceIDURN != "urn:uuid:00000000-0000-4000-8000-000000000001" {
		t.Fatalf("UE instance ID URN = %q, want generic URN default", cfg.MCX.UEInstanceIDURN)
	}
}

func TestConfigDerivesRealmFromPLMNWhenRealmIsUnset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("ims:\n  mcc: \"001\"\n  mnc: \"01\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IMS.Realm != "ims.mnc01.mcc001.3gppnetwork.org" {
		t.Fatalf("realm = %q, want PLMN-derived realm", cfg.IMS.Realm)
	}
	if cfg.MCX.SIPIdentity != "sip:mcptt-as@ims.mnc01.mcc001.3gppnetwork.org" {
		t.Fatalf("sip identity = %q, want PLMN-derived identity", cfg.MCX.SIPIdentity)
	}
}

func TestConfigUsesExplicitNetworkValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := []byte(`
sip:
  advertise_host: "198.51.100.10"
cms:
  listen: ":9100"
ims:
  mcc: "999"
  mnc: "99"
  realm: "ims.custom.example"
mcx:
  sip_identity: "sip:as@ims.custom.example"
  server_name: "sip:as.ims.custom.example"
  default_user_identity: "sip:default-user@ims.custom.example"
  default_group_uri: "sip:default-group@ims.custom.example"
  ue_xui_uri: "sip:ue@ims.custom.example"
  ue_instance_id_urn: "urn:gsma:imei:000000000000000"
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IMS.Realm != "ims.custom.example" {
		t.Fatalf("realm = %q, want explicit realm", cfg.IMS.Realm)
	}
	if cfg.CMS.XCAPRoot != "http://198.51.100.10:9100/xcap-root" {
		t.Fatalf("xcap root = %q, want advertise-host/listen-derived root", cfg.CMS.XCAPRoot)
	}
	if cfg.MCX.DefaultUserIdentity != "sip:default-user@ims.custom.example" {
		t.Fatalf("default user identity = %q, want explicit value", cfg.MCX.DefaultUserIdentity)
	}
	if cfg.MCX.DefaultGroupURI != "sip:default-group@ims.custom.example" {
		t.Fatalf("default group URI = %q, want explicit value", cfg.MCX.DefaultGroupURI)
	}
	if cfg.MCX.UEXUIURI != "sip:ue@ims.custom.example" {
		t.Fatalf("UE XUI URI = %q, want explicit value", cfg.MCX.UEXUIURI)
	}
	if cfg.MCX.UEInstanceIDURN != "urn:gsma:imei:000000000000000" {
		t.Fatalf("UE instance ID URN = %q, want explicit value", cfg.MCX.UEInstanceIDURN)
	}
}

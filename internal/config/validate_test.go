package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config must validate, got: %v", err)
	}
}

func TestValidateRejectsUnknownEnumValues(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantMsg string
	}{
		{"sip transport", func(c *Config) { c.SIP.Transport = "sctp" }, "sip.transport"},
		{"notify route order", func(c *Config) { c.SIP.NotifyRouteSetOrder = "backwards" }, "sip.notify_route_set_order"},
		{"media direction", func(c *Config) { c.Media.Direction = "sendrec" }, "media.direction"},
		{"database driver", func(c *Config) { c.Database.Driver = "mysql" }, "database.driver"},
		{"log level", func(c *Config) { c.Log.Level = "verbose" }, "log.level"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected %s to be rejected", tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error %q does not name the offending field %q", err, tc.wantMsg)
			}
		})
	}
}

// Setting audio_port to 40001 derives an rtcp_port of 40002, which is also the
// default floor_control_port. Before validation existed this bound two
// listeners to the same UDP port and failed at runtime instead of at startup.
func TestValidateRejectsDerivedMediaPortCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("media:\n  enabled: true\n  audio_port: 40001\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected the derived rtcp/floor port collision to be rejected")
	}
	if !strings.Contains(err.Error(), "media ports must differ") {
		t.Fatalf("error %q does not explain the collision", err)
	}
}

func TestValidateRejectsDuplicateMediaPorts(t *testing.T) {
	cfg := Default()
	cfg.Media.Enabled = true
	cfg.Media.FloorControlPort = cfg.Media.AudioPort

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected duplicate media ports to be rejected")
	}
	if !strings.Contains(err.Error(), "media.audio_port") || !strings.Contains(err.Error(), "media.floor_control_port") {
		t.Fatalf("error %q does not name both colliding fields", err)
	}
}

func TestValidateSkipsMediaPortsWhenMediaDisabled(t *testing.T) {
	cfg := Default()
	cfg.Media.Enabled = false
	cfg.Media.FloorControlPort = cfg.Media.AudioPort

	if err := cfg.Validate(); err != nil {
		t.Fatalf("media ports must not be checked while media is disabled, got: %v", err)
	}
}

func TestValidateRejectsMalformedListenAddresses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"missing port", func(c *Config) { c.API.Listen = "127.0.0.1" }, "api.listen"},
		{"non-numeric port", func(c *Config) { c.CMS.Listen = "127.0.0.1:http" }, "cms.listen"},
		{"port out of range", func(c *Config) { c.SIP.UDPListen = ":70000" }, "sip.udp_listen"},
		{"advertise port zero is defaulted", func(c *Config) { c.SIP.AdvertisePort = -1 }, "sip.advertise_port"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected %s to be rejected", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the offending field %q", err, tc.want)
			}
		})
	}
}

func TestValidateRejectsMalformedOptionsInterval(t *testing.T) {
	cfg := Default()
	cfg.SIP.Options.Enabled = true
	cfg.SIP.Options.Interval = "30 seconds"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected a malformed options interval to be rejected")
	}
	if !strings.Contains(err.Error(), "sip.options.interval") {
		t.Fatalf("error %q does not name the offending field", err)
	}
}

func TestValidateIgnoresOptionsIntervalWhenOptionsDisabled(t *testing.T) {
	cfg := Default()
	cfg.SIP.Options.Enabled = false
	cfg.SIP.Options.Interval = "30 seconds"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("interval must not be checked while options are disabled, got: %v", err)
	}
}

// Validate collects every problem so a bad file can be fixed in one pass.
func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	cfg := Default()
	cfg.SIP.Transport = "sctp"
	cfg.Log.Level = "verbose"
	cfg.API.Listen = "127.0.0.1"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected multiple problems to be reported")
	}
	for _, want := range []string{"sip.transport", "log.level", "api.listen"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q omits %q; all problems should be reported together", err, want)
		}
	}
}

func TestLoadFlagsMissingFileAsDefaulted(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("a missing file is documented to fall back to defaults, got: %v", err)
	}
	if !cfg.UsedDefaults {
		t.Fatal("UsedDefaults must be set so a mistyped -c path can be surfaced")
	}
}

func TestLoadDoesNotFlagDefaultsForAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("log:\n  level: \"debug\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UsedDefaults {
		t.Fatal("UsedDefaults must stay false when the file was read")
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("log level = %q, want the value from the file", cfg.Log.Level)
	}
}

// The example config is what operators copy to /opt/vectorcore/etc/mcxas.yaml
// during `make install`, so it must load cleanly.
func TestShippedExampleConfigIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "config", "config.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example config not present at %s", path)
	}

	if _, err := Load(path); err != nil {
		t.Fatalf("shipped config/config.yaml must load cleanly, got: %v", err)
	}
}

func TestLoadRejectsInvalidFileAndNamesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("database:\n  driver: \"mysql\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an invalid driver to fail the load")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q should name the offending file", err)
	}
	if !strings.Contains(err.Error(), "database.driver") {
		t.Fatalf("error %q should name the offending field", err)
	}
}

// The shim hands out credentials, so enabling it without a registered redirect
// URI must be refused rather than silently allowing any target.
func TestValidateRejectsEnabledShimWithoutRegisteredRedirect(t *testing.T) {
	cfg := Default()
	cfg.IDMS.DevelopmentShimEnabled = true

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected the enabled shim to require a registered redirect URI")
	}
	if !strings.Contains(err.Error(), "idms.allowed_redirect_uris") {
		t.Fatalf("error %q does not name the offending field", err)
	}
}

func TestValidateRejectsRelativeRedirectURI(t *testing.T) {
	cfg := Default()
	cfg.IDMS.DevelopmentShimEnabled = true
	cfg.IDMS.AllowedRedirectURIs = []string{"/callback"}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected a relative redirect URI to be rejected")
	}
	if !strings.Contains(err.Error(), "absolute URI") {
		t.Fatalf("error %q does not explain the requirement", err)
	}
}

func TestValidateAcceptsEnabledShimWithRegisteredRedirect(t *testing.T) {
	cfg := Default()
	cfg.IDMS.DevelopmentShimEnabled = true
	cfg.IDMS.AllowedRedirectURIs = []string{"http://192.0.2.20:9000/callback"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a properly configured shim must validate, got: %v", err)
	}
}

// The shim must stay off unless deliberately switched on.
func TestDefaultConfigLeavesTheShimDisabled(t *testing.T) {
	if Default().IDMS.DevelopmentShimEnabled {
		t.Fatal("the development identity shim must default to disabled")
	}
}

func TestValidateRequiresKeypairWhenTLSEnabled(t *testing.T) {
	cfg := Default()
	cfg.TLS.Enabled = true

	err := cfg.Validate()
	if err == nil {
		t.Fatal("enabling TLS without a keypair must be rejected")
	}
	for _, want := range []string{"tls.cert_file", "tls.key_file"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err, want)
		}
	}
}

func TestValidateRejectsUnknownTLSMinVersion(t *testing.T) {
	cfg := Default()
	cfg.TLS.MinVersion = "1.1"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "tls.min_version") {
		t.Fatalf("expected tls.min_version to be rejected, got: %v", err)
	}
}

// Derived URLs must follow the listeners: advertising http endpoints while
// serving only https leaves every client pointed at a scheme that no longer
// answers.
func TestDerivedURLsUseHTTPSWhenTLSEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "tls:\n  enabled: true\n  cert_file: \"/etc/mcxas/cert.pem\"\n  key_file: \"/etc/mcxas/key.pem\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.CMS.XCAPRoot, "https://") {
		t.Fatalf("xcap root = %q, want https when TLS is enabled", cfg.CMS.XCAPRoot)
	}
	if !strings.HasPrefix(cfg.MCX.IDMSAuthEndpoint, "https://") {
		t.Fatalf("idms auth endpoint = %q, want https when TLS is enabled", cfg.MCX.IDMSAuthEndpoint)
	}
	if !strings.HasPrefix(cfg.MCX.HTTPProxyURI, "https://") {
		t.Fatalf("http proxy uri = %q, want https when TLS is enabled", cfg.MCX.HTTPProxyURI)
	}
}

func TestDerivedURLsUseHTTPWhenTLSDisabled(t *testing.T) {
	cfg := Default()
	if !strings.HasPrefix(cfg.CMS.XCAPRoot, "http://") {
		t.Fatalf("xcap root = %q, want http while TLS is disabled", cfg.CMS.XCAPRoot)
	}
}

// A SIP TLS listener without certificates would either fail at bind or,
// worse, tempt a fallback to plaintext; refuse the configuration instead.
func TestValidateRejectsSIPTLSListenerWithoutTLSSection(t *testing.T) {
	cfg := Default()
	cfg.SIP.TLSListen = ":5061"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sip.tls_listen") {
		t.Fatalf("expected sip.tls_listen to require the tls section, got: %v", err)
	}
}

func TestValidateAcceptsSIPTLSListenerWithTLSSection(t *testing.T) {
	cfg := Default()
	cfg.SIP.TLSListen = ":5061"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/etc/mcxas/cert.pem"
	cfg.TLS.KeyFile = "/etc/mcxas/key.pem"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a fully specified SIP TLS listener must validate, got: %v", err)
	}
}

func TestValidateRequiresJWKSWhenServiceAuthorizationEnabled(t *testing.T) {
	cfg := Default()
	cfg.SIP.Auth.RequireServiceAuthorization = true

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sip.auth.trusted_jwks_file") {
		t.Fatalf("expected trusted_jwks_file to be required, got: %v", err)
	}
}

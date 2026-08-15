package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	API      APIConfig      `yaml:"api"`
	SIP      SIPConfig      `yaml:"sip"`
	CMS      CMSConfig      `yaml:"cms"`
	Media    MediaConfig    `yaml:"media"`
	Database DatabaseConfig `yaml:"database"`
	Log      LogConfig      `yaml:"log"`
	IMS      IMSConfig      `yaml:"ims"`
	MCX      MCXConfig      `yaml:"mcx"`
	IDMS     IDMSConfig     `yaml:"idms"`
	KMS      KMSConfig      `yaml:"kms"`
	TLS      TLSConfig      `yaml:"tls"`

	// UsedDefaults reports that the file named on the command line did not
	// exist and the built-in defaults were used instead. Load treats that as
	// success because it is the documented behaviour, but callers should
	// surface it: a mistyped -c path otherwise starts a loopback server on a
	// placeholder realm without saying so.
	UsedDefaults bool `yaml:"-"`
}

type APIConfig struct {
	Listen string `yaml:"listen"`
}

type SIPConfig struct {
	// Mode selects the server's SIP posture. "standalone" (the default)
	// terminates client REGISTERs directly, standing in for a SIP core so a
	// lab without IMS works. "application_server" is the TS 23.280 posture:
	// an AS behind a SIP core on ISC, consuming third-party REGISTERs whose
	// message/sip body carries the client's original REGISTER (TS 24.379
	// clause 7.3.2) and binding the MCPTT ID from its access token.
	Mode                string        `yaml:"mode"`
	UDPListen           string        `yaml:"udp_listen"`
	TCPListen           string        `yaml:"tcp_listen"`
	TLSListen           string        `yaml:"tls_listen"`
	AdvertiseHost       string        `yaml:"advertise_host"`
	AdvertisePort       int           `yaml:"advertise_port"`
	Transport           string        `yaml:"transport"`
	RecordRoute         bool          `yaml:"record_route"`
	NotifyRouteSetOrder string        `yaml:"notify_route_set_order"`
	Options             OptionsConfig `yaml:"options"`
	// RemoteGroups homes specific groups at another MC system's controlling
	// function (design D3). Groups not listed here home locally.
	RemoteGroups []RemoteGroupConfig `yaml:"remote_groups"`
	Auth         SIPAuthConfig       `yaml:"auth"`
	Adhoc        AdhocConfig         `yaml:"adhoc"`
	PrivateCall  PrivateCallConfig   `yaml:"private_call"`
	Emergency    EmergencyConfig     `yaml:"emergency"`
	// MaxAffiliationsN2 is the N2 limit of TS 22.280: the maximum number of
	// simultaneous group affiliations per user, advertised as
	// <MaxAffiliationsN2> in the generated user profile. 0 means the
	// default of 200.
	MaxAffiliationsN2 int `yaml:"max_affiliations_n2"`
	// Location configures the TS 24.379 clause 13.2 location procedures.
	Location LocationConfig `yaml:"location"`
	// MCData configures the TS 24.282 clause 11.1 transmission limits.
	MCData MCDataConfig `yaml:"mcdata"`
	// PreEstablished configures pre-established sessions (TS 24.379 clause 8).
	PreEstablished PreEstablishedConfig `yaml:"preestablished"`
}

// PreEstablishedConfig drives TS 24.379 clause 8 pre-established sessions.
type PreEstablishedConfig struct {
	// Enabled default true; false refuses establishment INVITEs.
	Enabled bool `yaml:"enabled"`
	// PSI is the public service identity clients INVITE to establish a
	// session; empty means sip:mcptt-pes@<realm>.
	PSI string `yaml:"psi"`
}

// MCDataConfig stands in for the size elements of the MCData service
// configuration document (TS 24.484) consulted by TS 24.282 clause 11.1.
type MCDataConfig struct {
	// MaxSDSSizeBytes is <max-data-size-sds-bytes>: the mcdata-payload size
	// cap for SDS (warnings 217/218). 0 means no limit.
	MaxSDSSizeBytes int `yaml:"max_sds_size_bytes"`
	// MaxSingleRequestBytes is the per-request transmission cap of clause
	// 11.1 steps 7-8 (warning 208). 0 means no limit.
	MaxSingleRequestBytes int `yaml:"max_single_request_bytes"`
}

// LocationConfig drives the clause 13.2.2 location reporting configuration
// the participating function pushes to registered clients.
type LocationConfig struct {
	// ReportIntervalSeconds is the <PeriodicReport> trigger interval; 0
	// disables the configuration push (clients may still report).
	ReportIntervalSeconds int `yaml:"report_interval_seconds"`
}

// EmergencyConfig stands in for the <emergency-call> elements of the MCPTT
// service configuration document (TS 24.484).
type EmergencyConfig struct {
	// GroupTimeLimitSeconds is the <group-time-limit>: the TNG2 in-progress
	// emergency group call timer value (TS 24.379 clause 6.3.3.1.16).
	// 0 disables the timer and the emergency state persists until the
	// group's last leg ends.
	GroupTimeLimitSeconds int `yaml:"group_time_limit_seconds"`
}

// AdhocConfig stands in for the ad hoc group call elements of the MCPTT
// service configuration document (TS 24.379 clause 17.4.2.2 steps 5 and 6)
// until the CMS generates one: whether the system supports ad hoc group
// calls, and the maximum number of participants per call.
type AdhocConfig struct {
	// Enabled defaults to true; false makes the controlling function answer
	// ad hoc originations 403 with warning "186".
	Enabled bool `yaml:"enabled"`
	// MaxParticipants caps the participant list (warning "189" when
	// exceeded); 0 means no limit.
	MaxParticipants int `yaml:"max_participants"`
	// MaxCallDurationSeconds is the ad hoc group call timer of TS 24.379
	// clause 17.4.2.2 step 13 (max-duration in the service configuration);
	// 0 disables it.
	MaxCallDurationSeconds int `yaml:"max_call_duration_seconds"`
}

// PrivateCallConfig stands in for the per-user "max private call duration"
// of TS 24.379 clause 11.1.1.4.1 step 10 until user profiles carry it.
type PrivateCallConfig struct {
	// MaxDurationSeconds bounds a private call; 0 disables the timer.
	MaxDurationSeconds int `yaml:"max_duration_seconds"`
}

// SIPAuthConfig controls service authorization on the SIP interface
// (TS 33.180 clause 5.1.3.2.3): the access token carried in the
// service-authorization PUBLISH is validated before the asserted MCPTT
// identity is believed.
type SIPAuthConfig struct {
	RequireServiceAuthorization bool `yaml:"require_service_authorization"`
	// TrustedJWKSFile holds the JWK set whose keys sign acceptable access
	// tokens. The development shim exports its set at /idms/jwks.json.
	TrustedJWKSFile string `yaml:"trusted_jwks_file"`
	// TrustedIssuer, when set, must equal the token's iss claim.
	TrustedIssuer string `yaml:"trusted_issuer"`
}

// RemoteGroupConfig binds one group to a remote controlling MCPTT function
// (TS 24.379 clause 6.3.3 at a peer system, an IWF, or a gateway server).
type RemoteGroupConfig struct {
	// GroupURI is the MCPTT group identity homed remotely.
	GroupURI string `yaml:"group_uri"`
	// ControllingPSI is the public service identity of the remote controlling
	// function; it becomes the Request-URI of the forwarded INVITE.
	ControllingPSI string `yaml:"controlling_psi"`
	// Target is the host:port the INVITE is sent to.
	Target string `yaml:"target"`
	// Transport is udp, tcp or tls; empty means udp.
	Transport string `yaml:"transport"`
}

type OptionsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
}

type CMSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`
	XCAPRoot string `yaml:"xcap_root"`
	// RequireAuthorization enforces TS 24.482 HTTP authorisation on the XCAP
	// endpoints: requests must carry an RFC 6750 bearer access token (or an
	// X-3GPP-Asserted-Identity from a trusted proxy) or be refused 403. The
	// token is validated against sip.auth.trusted_jwks_file. Off by default
	// so the unauthenticated bootstrap fetch of ue-init-config keeps working
	// in development; production deployments should enable it.
	RequireAuthorization bool `yaml:"require_authorization"`
}

// KMSConfig configures the Key Management Server of TS 33.180 clause 5.3
// and its provisioning interface of Annex D.
type KMSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	// KMSURI identifies the security domain. It is hashed into every
	// MIKEY-SAKKE UID (TS 33.180 clause F.2.1), so changing it
	// invalidates all key material this KMS has issued.
	KMSURI string `yaml:"kms_uri"`
	// CertURI names the root certificate. Clause 5.3.5: a client
	// replaces a held certificate when it receives one bearing the same
	// CertUri, which is how a certificate is updated in place.
	CertURI string `yaml:"cert_uri"`
	Issuer  string `yaml:"issuer"`
	// KMSID is the optional KmsId of table D.3.1-1, identifying the
	// provider of the response.
	KMSID string `yaml:"kms_id"`
	// KeyMaterialFile holds the domain master secrets. It is deliberately
	// a separate file rather than fields here: these secrets derive every
	// user key in the domain and must never reach a configuration
	// repository. The file is created with owner-only permissions on
	// first start and refused if it is readable more widely.
	KeyMaterialFile string `yaml:"key_material_file"`
	// KeyPeriodSeconds and KeyPeriodOffsetSeconds are the UserKeyPeriod
	// and UserKeyOffset of table D.3.2.2-1, the segmentation of time into
	// key periods. The default is the 2592000 seconds (four weeks) the
	// specification uses in its own examples.
	KeyPeriodSeconds       int64 `yaml:"key_period_seconds"`
	KeyPeriodOffsetSeconds int64 `yaml:"key_period_offset_seconds"`
	// DomainList is the optional KmsDomainList of the certificate.
	DomainList []string `yaml:"domain_list"`
	// ServerIdentities are the identities a client may request key
	// material for besides its own, which is how the group management
	// server identity of clause 5.7.1 gets provisioned.
	ServerIdentities []string `yaml:"server_identities"`
}

type MediaConfig struct {
	Enabled                   bool   `yaml:"enabled"`
	ListenHost                string `yaml:"listen_host"`
	AdvertiseHost             string `yaml:"advertise_host"`
	Direction                 string `yaml:"direction"`
	AudioPort                 int    `yaml:"audio_port"`
	RTCPPort                  int    `yaml:"rtcp_port"`
	FloorControlPort          int    `yaml:"floor_control_port"`
	FloorAutoGrant            bool   `yaml:"floor_auto_grant"`
	FloorGrantDurationSeconds int    `yaml:"floor_grant_duration_seconds"`
	// FloorT1Seconds is timer T1 (End of RTP media) of TS 24.380 clause
	// 6.3.4.4.3, one instance per granted talker: a talker silent this long
	// loses the floor. Matches the <T1-end-of-rtp-media> the generated
	// service configuration advertises (default 5). -1 disables the sweep.
	FloorT1Seconds    int   `yaml:"floor_t1_seconds"`
	LogPackets        bool  `yaml:"log_packets"`
	LogPacketInterval int64 `yaml:"log_packet_interval"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type LogConfig struct {
	File  string `yaml:"file"`
	Level string `yaml:"level"`
}

// TLSConfig covers the HTTP listeners (OAM API and CMS/XCAP). TS 33.180
// makes TLS on HTTP-1 mandatory, so a deployment without it is a lab
// convenience, not a configuration of equal standing.
//
// SIP transport security is a separate concern with its own signalling
// implications (sips URIs, transport parameters) and is configured under sip
// when implemented.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ClientCAFile, when set, additionally requires and verifies a client
	// certificate against this CA bundle (mutual TLS).
	ClientCAFile string `yaml:"client_ca_file"`
	// PeerCAFile is appended to the system roots when this server dials TLS
	// peers itself (outbound SIP over TLS). Deployments on an internal PKI
	// point this at their issuing CA.
	PeerCAFile string `yaml:"peer_ca_file"`
	MinVersion string `yaml:"min_version"`
}

// IDMSConfig controls the built-in identity shim.
//
// The shim is NOT an implementation of 3GPP TS 24.482. It performs no user
// authentication at all: any caller able to reach the token endpoint is issued
// a token asserting a provisioned subscriber's MCPTT identity. It exists for
// bring-up against a client that expects an OIDC endpoint, and is disabled
// unless explicitly switched on.
type IDMSConfig struct {
	DevelopmentShimEnabled bool     `yaml:"development_shim_enabled"`
	SigningKeyFile         string   `yaml:"signing_key_file"`
	Issuer                 string   `yaml:"issuer"`
	AllowedRedirectURIs    []string `yaml:"allowed_redirect_uris"`
	// Enabled turns on the conformant OpenID Connect provider of TS 33.180
	// Annex B / TS 24.482: authorization code flow with mandatory PKCE
	// (S256), password authentication of provisioned users (3gpp:acr:password),
	// MC service scopes, and refresh tokens. Mutually exclusive with the
	// development shim.
	Enabled bool `yaml:"enabled"`
	// AllowedClientIDs is the client registration list (TS 33.180 clause
	// B.3); empty permits no client.
	AllowedClientIDs []string `yaml:"allowed_client_ids"`
	// AccessTokenTTLSeconds bounds issued access tokens (default 3600).
	AccessTokenTTLSeconds int `yaml:"access_token_ttl_seconds"`
	// RefreshTokenTTLSeconds bounds refresh tokens (default 30 days).
	RefreshTokenTTLSeconds int `yaml:"refresh_token_ttl_seconds"`
	// Partners are the primary IdM services of other MC domains whose
	// security tokens this one accepts (TS 33.180 clause B.7.4). Each
	// entry pins an issuer to the JWKS its tokens are signed with; an
	// assertion that matches no entry is refused.
	Partners []PartnerIdMS `yaml:"partners"`
}

// PartnerIdMS identifies a partner MC domain's IdM service for the
// inter-domain authorisation of TS 33.180 Annex B.7.
type PartnerIdMS struct {
	Issuer   string `yaml:"issuer"`
	JWKSFile string `yaml:"jwks_file"`
}

type IMSConfig struct {
	MCC   string `yaml:"mcc"`
	MNC   string `yaml:"mnc"`
	Realm string `yaml:"realm"`
}

type MCXConfig struct {
	SIPIdentity         string `yaml:"sip_identity"`
	ServerName          string `yaml:"server_name"`
	DefaultUserIdentity string `yaml:"default_user_identity"`
	DefaultGroupURI     string `yaml:"default_group_uri"`
	UEXUIURI            string `yaml:"ue_xui_uri"`
	UEInstanceIDURN     string `yaml:"ue_instance_id_urn"`
	CMSURI              string `yaml:"cms_uri"`
	GMSURI              string `yaml:"gms_uri"`
	KMSURI              string `yaml:"kms_uri"`
	IDMSAuthEndpoint    string `yaml:"idms_auth_endpoint"`
	IDMSTokenEndpoint   string `yaml:"idms_token_endpoint"`
	HTTPProxyURI        string `yaml:"http_proxy_uri"`
}

func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.UsedDefaults = true
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	present := yamlPresence(b)
	if !present["sip.advertise_host"] {
		cfg.SIP.AdvertiseHost = ""
	}
	if !present["media.advertise_host"] {
		cfg.Media.AdvertiseHost = ""
	}
	if !present["cms.xcap_root"] {
		cfg.CMS.XCAPRoot = ""
	}
	if !present["ims.realm"] {
		cfg.IMS.Realm = ""
	}
	if !present["mcx.sip_identity"] {
		cfg.MCX.SIPIdentity = ""
	}
	if !present["mcx.server_name"] {
		cfg.MCX.ServerName = ""
	}
	if !present["mcx.default_user_identity"] {
		cfg.MCX.DefaultUserIdentity = ""
	}
	if !present["mcx.default_group_uri"] {
		cfg.MCX.DefaultGroupURI = ""
	}
	if !present["mcx.ue_xui_uri"] {
		cfg.MCX.UEXUIURI = ""
	}
	if !present["mcx.ue_instance_id_urn"] {
		cfg.MCX.UEInstanceIDURN = ""
	}
	if !present["mcx.cms_uri"] {
		cfg.MCX.CMSURI = ""
	}
	if !present["mcx.gms_uri"] {
		cfg.MCX.GMSURI = ""
	}
	if !present["mcx.kms_uri"] {
		cfg.MCX.KMSURI = ""
	}
	if !present["mcx.idms_auth_endpoint"] {
		cfg.MCX.IDMSAuthEndpoint = ""
	}
	if !present["mcx.idms_token_endpoint"] {
		cfg.MCX.IDMSTokenEndpoint = ""
	}
	if !present["mcx.http_proxy_uri"] {
		cfg.MCX.HTTPProxyURI = ""
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid configuration in %s:\n%w", path, err)
	}
	return cfg, nil
}

func Default() Config {
	cfg := Config{}
	cfg.SIP.RecordRoute = true
	cfg.SIP.Adhoc.Enabled = true
	cfg.SIP.PreEstablished.Enabled = true
	// TNG2 default (TS 24.379 clause 6.3.3.1.16); explicit 0 disables.
	cfg.SIP.Emergency.GroupTimeLimitSeconds = 300
	cfg.Media.Enabled = true
	cfg.Media.FloorAutoGrant = true
	cfg.applyDefaults()
	return cfg
}

func (c *Config) applyDefaults() {
	if c.API.Listen == "" {
		c.API.Listen = ":8080"
	}
	if c.SIP.UDPListen == "" {
		c.SIP.UDPListen = ":5060"
	}
	if c.SIP.TCPListen == "" {
		c.SIP.TCPListen = ":5060"
	}
	if c.SIP.AdvertiseHost == "" {
		c.SIP.AdvertiseHost = advertiseHostFromListen(c.SIP.UDPListen)
	}
	if c.SIP.AdvertisePort == 0 {
		c.SIP.AdvertisePort = 5060
	}
	if c.SIP.Transport == "" {
		c.SIP.Transport = "udp"
	}
	c.SIP.Transport = strings.ToLower(c.SIP.Transport)
	if c.SIP.Mode == "" {
		c.SIP.Mode = "standalone"
	}
	c.SIP.Mode = strings.ToLower(strings.TrimSpace(c.SIP.Mode))
	if c.SIP.NotifyRouteSetOrder == "" {
		// RFC 3261 §12.2.1.1: use the route set in stored order (Record-Routes
		// as received, top-to-bottom). This puts S-CSCF first and P-CSCF last,
		// giving AS → S-CSCF → P-CSCF → UE — the correct IMS terminating path.
		c.SIP.NotifyRouteSetOrder = "preserve"
	}
	c.SIP.NotifyRouteSetOrder = strings.ToLower(c.SIP.NotifyRouteSetOrder)
	if c.SIP.Options.Interval == "" {
		c.SIP.Options.Interval = "30s"
	}
	if c.CMS.Listen == "" {
		c.CMS.Listen = ":8100"
	}
	if c.KMS.Listen == "" {
		c.KMS.Listen = ":8110"
	}
	if c.KMS.KMSURI == "" {
		c.KMS.KMSURI = "kms." + c.IMS.Realm
	}
	if c.KMS.CertURI == "" {
		c.KMS.CertURI = "cert1." + c.KMS.KMSURI
	}
	if c.KMS.KeyMaterialFile == "" {
		c.KMS.KeyMaterialFile = "kms-domain-keys.txt"
	}
	if c.KMS.KeyPeriodSeconds == 0 {
		c.KMS.KeyPeriodSeconds = 2592000
	}
	if c.CMS.XCAPRoot == "" {
		c.CMS.XCAPRoot = c.httpScheme() + "://" + net.JoinHostPort(c.SIP.AdvertiseHost, listenPort(c.CMS.Listen, "8100")) + "/xcap-root"
	}
	if c.Media.ListenHost == "" {
		c.Media.ListenHost = "0.0.0.0"
	}
	if c.Media.AdvertiseHost == "" {
		c.Media.AdvertiseHost = c.SIP.AdvertiseHost
	}
	if c.Media.Direction == "" {
		c.Media.Direction = "sendrecv"
	}
	c.Media.Direction = strings.ToLower(c.Media.Direction)
	if c.Media.AudioPort == 0 {
		c.Media.AudioPort = 40000
	}
	if c.Media.RTCPPort == 0 {
		c.Media.RTCPPort = c.Media.AudioPort + 1
	}
	if c.Media.FloorControlPort == 0 {
		c.Media.FloorControlPort = 40002
	}
	if c.Media.FloorT1Seconds == 0 {
		// The generated service configuration advertises PT5S.
		c.Media.FloorT1Seconds = 5
	}
	if c.Media.FloorGrantDurationSeconds == 0 {
		c.Media.FloorGrantDurationSeconds = 30
	}
	if c.Media.LogPacketInterval == 0 {
		c.Media.LogPacketInterval = 100
	}
	if c.Database.Driver == "" {
		c.Database.Driver = "sqlite"
	}
	c.Database.Driver = strings.ToLower(c.Database.Driver)
	if c.Database.DSN == "" {
		c.Database.DSN = "mcxas.db"
	}
	if c.TLS.MinVersion == "" {
		c.TLS.MinVersion = "1.2"
	}
	c.TLS.MinVersion = strings.TrimSpace(c.TLS.MinVersion)
	if c.Log.File == "" {
		c.Log.File = "mcxas.log"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.IMS.Realm == "" {
		c.IMS.Realm = realmFromPLMN(c.IMS.MCC, c.IMS.MNC)
	}
	if c.MCX.SIPIdentity == "" {
		c.MCX.SIPIdentity = "sip:mcptt-as@" + c.IMS.Realm
	}
	if c.MCX.ServerName == "" {
		c.MCX.ServerName = "sip:mcptt-as." + c.IMS.Realm
	}
	if c.MCX.DefaultUserIdentity == "" {
		c.MCX.DefaultUserIdentity = "sip:mcptt-user@" + c.IMS.Realm
	}
	if c.MCX.DefaultGroupURI == "" {
		c.MCX.DefaultGroupURI = "sip:mcptt-group@" + c.IMS.Realm
	}
	if c.MCX.UEXUIURI == "" {
		c.MCX.UEXUIURI = c.MCX.DefaultUserIdentity
	}
	if c.MCX.UEInstanceIDURN == "" {
		c.MCX.UEInstanceIDURN = "urn:uuid:00000000-0000-4000-8000-000000000001"
	}
	if c.MCX.CMSURI == "" {
		c.MCX.CMSURI = c.MCX.SIPIdentity
	}
	if c.MCX.GMSURI == "" {
		c.MCX.GMSURI = c.MCX.SIPIdentity
	}
	if c.MCX.KMSURI == "" {
		c.MCX.KMSURI = c.MCX.SIPIdentity
	}
	apiBase := c.httpScheme() + "://" + net.JoinHostPort(c.SIP.AdvertiseHost, listenPort(c.API.Listen, "8080"))
	if c.MCX.IDMSAuthEndpoint == "" {
		c.MCX.IDMSAuthEndpoint = apiBase + "/idms/authorize"
	}
	if c.MCX.IDMSTokenEndpoint == "" {
		c.MCX.IDMSTokenEndpoint = apiBase + "/idms/token"
	}
	if c.MCX.HTTPProxyURI == "" {
		c.MCX.HTTPProxyURI = apiBase
	}
}

// httpScheme is the scheme derived URLs advertise. Derivation runs after the
// TLS section is unmarshalled, so the advertised endpoints follow the
// listeners.
func (c *Config) httpScheme() string {
	if c.TLS.Enabled {
		return "https"
	}
	return "http"
}

func advertiseHostFromListen(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1"
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1"
	}
	return host
}

func listenPort(listen, fallback string) string {
	_, port, err := net.SplitHostPort(listen)
	if err == nil && port != "" {
		return port
	}
	if _, err := strconv.Atoi(strings.TrimSpace(listen)); err == nil {
		return strings.TrimSpace(listen)
	}
	return fallback
}

func realmFromPLMN(mcc, mnc string) string {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	if mcc != "" && mnc != "" {
		return "ims.mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
	}
	return "ims.example.test"
}

func yamlPresence(b []byte) map[string]bool {
	present := map[string]bool{}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil || len(root.Content) == 0 {
		return present
	}
	doc := root.Content[0]
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key := doc.Content[i].Value
		val := doc.Content[i+1]
		present[key] = true
		if val.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(val.Content); j += 2 {
			present[key+"."+val.Content[j].Value] = true
		}
	}
	return present
}

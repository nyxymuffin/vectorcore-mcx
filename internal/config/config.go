package config

import (
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
}

type APIConfig struct {
	Listen string `yaml:"listen"`
}

type SIPConfig struct {
	UDPListen           string        `yaml:"udp_listen"`
	TCPListen           string        `yaml:"tcp_listen"`
	AdvertiseHost       string        `yaml:"advertise_host"`
	AdvertisePort       int           `yaml:"advertise_port"`
	Transport           string        `yaml:"transport"`
	RecordRoute         bool          `yaml:"record_route"`
	NotifyRouteSetOrder string        `yaml:"notify_route_set_order"`
	Options             OptionsConfig `yaml:"options"`
}

type OptionsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
}

type CMSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`
	XCAPRoot string `yaml:"xcap_root"`
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
	LogPackets                bool   `yaml:"log_packets"`
	LogPacketInterval         int64  `yaml:"log_packet_interval"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type LogConfig struct {
	File  string `yaml:"file"`
	Level string `yaml:"level"`
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
	return cfg, nil
}

func Default() Config {
	cfg := Config{}
	cfg.SIP.RecordRoute = true
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
	if c.CMS.XCAPRoot == "" {
		c.CMS.XCAPRoot = "http://" + net.JoinHostPort(c.SIP.AdvertiseHost, listenPort(c.CMS.Listen, "8100")) + "/xcap-root"
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
	apiBase := "http://" + net.JoinHostPort(c.SIP.AdvertiseHost, listenPort(c.API.Listen, "8080"))
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

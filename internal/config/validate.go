package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Validate reports whether the configuration is internally consistent and
// usable.
//
// It runs after applyDefaults, so every field it inspects holds either an
// explicit value or a default, and the enum fields have already been
// lower-cased. That lets the checks below be strict rather than lenient.
//
// All problems are collected and returned together, so a malformed file can be
// corrected in one pass instead of one startup attempt per mistake.
func (c Config) Validate() error {
	var problems []error
	problems = append(problems, c.validateEnums()...)
	problems = append(problems, c.validateListeners()...)
	problems = append(problems, c.validateMediaPorts()...)
	problems = append(problems, c.validateDurations()...)
	problems = append(problems, c.validateIDMS()...)
	problems = append(problems, c.validateTLS()...)
	return errors.Join(problems...)
}

// validateTLS refuses a TLS section that could not possibly serve. File
// existence is deliberately not checked here: Validate is pure, and the
// listener reports a missing or unreadable file with a better error at bind
// time.
func (c Config) validateTLS() []error {
	var problems []error
	if c.TLS.Enabled {
		if strings.TrimSpace(c.TLS.CertFile) == "" {
			problems = append(problems, errors.New("tls.cert_file: required when tls.enabled is true"))
		}
		if strings.TrimSpace(c.TLS.KeyFile) == "" {
			problems = append(problems, errors.New("tls.key_file: required when tls.enabled is true"))
		}
	}
	problems = append(problems, oneOf("tls.min_version", c.TLS.MinVersion, "1.2", "1.3"))
	return problems
}

// validateIDMS refuses configurations that would enable the development
// identity shim in a state where it cannot behave safely.
func (c Config) validateIDMS() []error {
	if !c.IDMS.DevelopmentShimEnabled {
		return nil
	}

	var problems []error
	if len(c.IDMS.AllowedRedirectURIs) == 0 {
		problems = append(problems, errors.New(
			"idms.allowed_redirect_uris: at least one URI is required when the development shim is enabled; "+
				"an unrestricted redirect_uri is an open redirect that leaks the authorization code"))
	}
	for i, raw := range c.IDMS.AllowedRedirectURIs {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme == "" || u.Host == "" {
			problems = append(problems, fmt.Errorf(
				"idms.allowed_redirect_uris[%d]: %q must be an absolute URI", i, raw))
		}
	}
	return problems
}

// validateEnums checks the fields that accept a fixed vocabulary. Without this
// a typo such as "sendrec" is silently accepted and then quietly ignored by
// whichever component reads it.
func (c Config) validateEnums() []error {
	return []error{
		oneOf("sip.mode", c.SIP.Mode, "standalone", "application_server"),
		oneOf("sip.transport", c.SIP.Transport, "udp", "tcp"),
		oneOf("sip.notify_route_set_order", c.SIP.NotifyRouteSetOrder, "preserve", "reverse"),
		oneOf("media.direction", c.Media.Direction, "sendrecv", "recvonly", "sendonly", "inactive"),
		oneOf("database.driver", c.Database.Driver, "sqlite", "postgres", "postgresql"),
		oneOf("log.level", c.Log.Level, "debug", "info", "warn", "warning", "error"),
	}
}

// validateListeners checks that every bind address parses and carries a usable
// port. Listen strings are validated even when their subsystem is disabled: a
// malformed value is a mistake whether or not it is currently reached.
func (c Config) validateListeners() []error {
	listeners := []struct {
		field string
		addr  string
	}{
		{"api.listen", c.API.Listen},
		{"cms.listen", c.CMS.Listen},
		{"sip.udp_listen", c.SIP.UDPListen},
		{"sip.tcp_listen", c.SIP.TCPListen},
	}

	var problems []error
	for _, l := range listeners {
		if err := validateListenAddr(l.field, l.addr); err != nil {
			problems = append(problems, err)
		}
	}
	if c.SIP.Auth.RequireServiceAuthorization && strings.TrimSpace(c.SIP.Auth.TrustedJWKSFile) == "" {
		problems = append(problems, errors.New(
			"sip.auth.trusted_jwks_file: required when require_service_authorization is true; without keys every request would be refused"))
	}
	for i, rg := range c.SIP.RemoteGroups {
		if strings.TrimSpace(rg.GroupURI) == "" || strings.TrimSpace(rg.ControllingPSI) == "" {
			problems = append(problems, fmt.Errorf(
				"sip.remote_groups[%d]: group_uri and controlling_psi are both required", i))
		}
		if t := strings.ToLower(strings.TrimSpace(rg.Transport)); t != "" && t != "udp" && t != "tcp" && t != "tls" {
			problems = append(problems, fmt.Errorf(
				"sip.remote_groups[%d].transport: %q is not valid (want udp, tcp or tls)", i, rg.Transport))
		}
	}
	if c.SIP.Adhoc.MaxParticipants < 0 {
		problems = append(problems, fmt.Errorf(
			"sip.adhoc.max_participants: %d is not valid (want 0 for no limit, or a positive count)",
			c.SIP.Adhoc.MaxParticipants))
	}
	if strings.TrimSpace(c.SIP.TLSListen) != "" {
		if err := validateListenAddr("sip.tls_listen", c.SIP.TLSListen); err != nil {
			problems = append(problems, err)
		}
		if !c.TLS.Enabled {
			problems = append(problems, errors.New(
				"sip.tls_listen: requires the tls section to be enabled, since the listener serves its certificates"))
		}
	}
	if err := validatePort("sip.advertise_port", c.SIP.AdvertisePort); err != nil {
		problems = append(problems, err)
	}
	return problems
}

// validateMediaPorts checks the three media listeners. They bind separate UDP
// sockets, so their ports must differ.
//
// The collision is easy to hit by accident: rtcp_port defaults to
// audio_port+1, so setting audio_port to 40001 derives an rtcp_port of 40002,
// which is also the default floor_control_port.
func (c Config) validateMediaPorts() []error {
	if !c.Media.Enabled {
		return nil
	}

	ports := []struct {
		field string
		port  int
	}{
		{"media.audio_port", c.Media.AudioPort},
		{"media.rtcp_port", c.Media.RTCPPort},
		{"media.floor_control_port", c.Media.FloorControlPort},
	}

	var problems []error
	for _, p := range ports {
		if err := validatePort(p.field, p.port); err != nil {
			problems = append(problems, err)
		}
	}

	seen := map[int]string{}
	for _, p := range ports {
		if other, duplicate := seen[p.port]; duplicate {
			problems = append(problems, fmt.Errorf(
				"media: %s and %s are both %d; the three media ports must differ",
				other, p.field, p.port))
			continue
		}
		seen[p.port] = p.field
	}
	return problems
}

// validateDurations checks the values that are parsed lazily elsewhere, so a
// malformed one fails at startup rather than at first use.
func (c Config) validateDurations() []error {
	var problems []error

	if c.SIP.Options.Enabled {
		if _, err := time.ParseDuration(c.SIP.Options.Interval); err != nil {
			problems = append(problems, fmt.Errorf(
				"sip.options.interval: %q is not a valid duration (for example \"30s\")",
				c.SIP.Options.Interval))
		}
	}

	if c.Media.Enabled {
		if c.Media.FloorGrantDurationSeconds < 0 {
			problems = append(problems, fmt.Errorf(
				"media.floor_grant_duration_seconds: %d must not be negative",
				c.Media.FloorGrantDurationSeconds))
		}
		if c.Media.LogPackets && c.Media.LogPacketInterval < 1 {
			problems = append(problems, fmt.Errorf(
				"media.log_packet_interval: %d must be at least 1 when media.log_packets is enabled",
				c.Media.LogPacketInterval))
		}
	}
	return problems
}

// oneOf reports an error when value is outside the allowed vocabulary.
func oneOf(field, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("%s: %q is not valid (want one of: %s)",
		field, value, strings.Join(allowed, ", "))
}

// validateListenAddr accepts the host:port form used by net.Listen, including
// the bare ":8080" shorthand.
func validateListenAddr(field, addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: %q is not a valid listen address (want host:port or :port)", field, addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%s: %q has a non-numeric port %q", field, addr, port)
	}
	return validatePort(field, n)
}

func validatePort(field string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s: port %d is out of range (want 1-65535)", field, port)
	}
	return nil
}

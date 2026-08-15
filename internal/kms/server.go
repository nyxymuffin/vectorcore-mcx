package kms

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/mctoken"
	"github.com/svinson1121/vectorcore-mcx/internal/tlsutil"
)

// The KMS provisioning interface of TS 33.180 Annex D. Requests are HTTP
// POSTs rooted under "/keymanagement/identity/v1" (clause D.2.1); the
// subdirectory selects the request type.
const RootPath = "/keymanagement/identity/v1"

// requestSkew is the window clause D.2.2 suggests for the Time field of
// an authenticated request ("e.g. 5 seconds"), widened to tolerate the
// clock drift of a real fleet.
const requestSkew = 30 * time.Second

// maxRequestBody bounds the XML a client may post.
const maxRequestBody = 64 << 10

type Server struct {
	cfg    config.Config
	domain *Domain
	tokens *mctoken.Validator

	// external holds certificates of other security domains, served by
	// the CertCache and Cert requests. Populated from configuration; a
	// KMS with no federation partners serves only its own certificate.
	external []KmsCertificate
}

// NewServer builds the KMS from configuration, loading or generating the
// domain's master secrets.
func NewServer(cfg config.Config) (*Server, error) {
	kc := cfg.KMS
	domain, err := LoadDomain(kc.KeyMaterialFile, Domain{
		KMSURI:  kc.KMSURI,
		CertURI: kc.CertURI,
		Issuer:  kc.Issuer,
		Period: KeyPeriod{
			LengthSeconds: kc.KeyPeriodSeconds,
			OffsetSeconds: kc.KeyPeriodOffsetSeconds,
		},
		DomainList: kc.DomainList,
	})
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, domain: domain}
	if cfg.SIP.Auth.TrustedJWKSFile != "" {
		validator, err := mctoken.New(cfg.SIP.Auth.TrustedJWKSFile, cfg.SIP.Auth.TrustedIssuer)
		if err != nil {
			return nil, fmt.Errorf("kms: token validator: %w", err)
		}
		s.tokens = validator
	}
	return s, nil
}

// Handler exposes the KMS routes, which lets the interface be mounted on
// an existing listener and lets tests drive it without a socket.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(RootPath+"/", s.handle)
	return mux
}

func (s *Server) Start(ctx context.Context) error {
	if !s.cfg.KMS.Enabled {
		return nil
	}
	tlsConf, err := tlsutil.ServerConfig(s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("kms listener: %w", err)
	}
	if tlsConf == nil {
		// Clause D.1: "All KMS communications are made via HTTPS." The
		// responses carry private user key material in the clear when the
		// clause D.2.2 security extension is not in use, so a plaintext
		// listener would publish it.
		return errors.New("kms: TLS is required; configure tls.cert_file and tls.key_file")
	}
	srv := &http.Server{
		Addr:         s.cfg.KMS.Listen,
		Handler:      s.Handler(),
		TLSConfig:    tlsConf,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("KMS server listening", "addr", s.cfg.KMS.Listen, "kms_uri", s.domain.KMSURI)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// handle routes a request by the subdirectory below the root path.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "KMS requests are made with POST", http.StatusMethodNotAllowed)
		return
	}
	// Clause D.2.4 puts a percent-encoded URI in the request path
	// ("/keyprov/sip%3Auser%40example.org"), so the split has to happen
	// on the escaped form. Splitting the decoded path would cut an
	// identity containing an encoded separator in half, and would leave
	// each segment decoded twice.
	rest := strings.Trim(strings.TrimPrefix(r.URL.EscapedPath(), RootPath), "/")
	segments := strings.Split(rest, "/")

	identity, err := s.authorize(r)
	if err != nil {
		// Clause 5.3.3 step 1: the request carries an access token that
		// authenticates the user. Without one the KMS cannot know whose
		// key material to derive, so there is nothing to serve.
		slog.Warn("KMS request refused", "path", r.URL.Path, "err", err)
		http.Error(w, "the KMS request is not authorised", http.StatusForbidden)
		return
	}

	req, err := s.decodeRequest(r, identity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch segments[0] {
	case "init":
		s.respondInit(w, r, identity, req)
	case "keyprov":
		s.respondKeyProv(w, r, identity, req, segments[1:])
	case "certcache":
		s.respondCertCache(w, r, identity, req, segments[1:])
	case "cert":
		s.respondCert(w, r, identity, req, segments[1:])
	default:
		// Lookup and redirect upload (clauses D.2.7 and D.2.8) are part
		// of the KMS discovery and redirect procedures, which are not
		// implemented; a KmsError is the schema's way of saying so.
		s.respondError(w, r, identity, req, http.StatusNotFound, 404,
			"this KMS does not offer the '"+segments[0]+"' request")
	}
}

// authorize applies clause 5.3.3 step 1: the request is authenticated by
// an RFC 6750 bearer access token, or by an identity asserted by a
// trusted HTTP proxy in the deployment of figure 5.3.3-1.
func (s *Server) authorize(r *http.Request) (string, error) {
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		scheme, token, ok := strings.Cut(auth, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return "", errors.New("authorization scheme is not Bearer")
		}
		if s.tokens == nil {
			return "", errors.New("no trusted JWKS configured; bearer tokens cannot be validated")
		}
		return s.tokens.Validate(strings.TrimSpace(token))
	}
	if asserted := strings.TrimSpace(r.Header.Get("X-3GPP-Asserted-Identity")); asserted != "" {
		return strings.Trim(asserted, `"<>`), nil
	}
	return "", errors.New("no access token and no asserted identity")
}

// decodeRequest parses and checks the KmsRequest payload. A request body
// is optional for the simplest clients, but when one is present the
// checks of clause D.2.2 apply.
func (s *Server) decodeRequest(r *http.Request, identity string) (*KmsRequest, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		return nil, fmt.Errorf("reading the request: %w", err)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return &KmsRequest{Version: requestVer, UserURI: identity}, nil
	}

	req := &KmsRequest{}
	if signed := (&SignedKmsRequest{}); xml.Unmarshal(body, signed) == nil && signed.Request != nil {
		req = signed.Request
	} else if err := xml.Unmarshal(body, req); err != nil {
		return nil, fmt.Errorf("the KmsRequest XML is not valid: %w", err)
	}

	// The KmsUri shall be the KMS's own URI.
	if got := strings.TrimSpace(req.KMSURI); got != "" && !strings.EqualFold(got, s.domain.KMSURI) {
		return nil, fmt.Errorf("the request is addressed to KMS %q", got)
	}
	// The ClientReqUrl shall be the resource URI the POST was sent to.
	if got := strings.TrimSpace(req.ClientReqURL); got != "" && !strings.HasSuffix(got, r.URL.Path) {
		return nil, fmt.Errorf("the ClientReqUrl %q does not match the request URI", got)
	}
	// The Time shall be recent.
	if got := strings.TrimSpace(req.Time); got != "" {
		when, err := parseXSDDateTime(got)
		if err != nil {
			return nil, fmt.Errorf("the request Time is not a dateTime: %w", err)
		}
		if drift := time.Since(when); drift > requestSkew || drift < -requestSkew {
			return nil, errors.New("the request Time is outside the accepted window")
		}
	}
	// A client may not ask for another user's key material. The token,
	// not the payload, decides whose keys these are.
	if got := strings.TrimSpace(req.UserURI); got != "" && !strings.EqualFold(got, identity) {
		return nil, errors.New("the UserUri does not match the authenticated identity")
	}
	req.UserURI = identity
	return req, nil
}

func parseXSDDateTime(v string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q", v)
}

// respondInit answers a KMS Initialize request with the domain's root
// certificate (clause D.3.1).
func (s *Server) respondInit(w http.ResponseWriter, r *http.Request, identity string, req *KmsRequest) {
	cert, err := s.domain.Certificate()
	if err != nil {
		s.respondError(w, r, identity, req, http.StatusInternalServerError, 500, err.Error())
		return
	}
	s.write(w, r, identity, req, &KmsMessage{
		Init: &KmsInit{Version: messageVer, Certificate: cert},
	})
}

// respondKeyProv answers a KMS KeyProvision request. Clause D.2.4 allows
// the request URI to name a specific identity and a specific time, both
// below the "keyprov" subdirectory.
func (s *Server) respondKeyProv(w http.ResponseWriter, r *http.Request, identity string, req *KmsRequest, rest []string) {
	target := identity
	if len(rest) > 0 && rest[0] != "" {
		requested, err := url.PathUnescape(rest[0])
		if err != nil {
			s.respondError(w, r, identity, req, http.StatusBadRequest, 400,
				"the requested URI is not a valid escaped identity")
			return
		}
		if !s.mayProvision(identity, requested) {
			s.respondError(w, r, identity, req, http.StatusForbidden, 403,
				"this user may not be provisioned by the authenticated client")
			return
		}
		target = requested
	}

	at := time.Now().UTC()
	number := s.domain.Period.Number(at)
	if len(rest) > 1 && rest[1] != "" {
		// The time is an NTP-UTC 64-bit timestamp, whose upper 32 bits
		// are the seconds the key period arithmetic works in.
		raw, err := strconv.ParseUint(rest[1], 16, 64)
		if err != nil {
			s.respondError(w, r, identity, req, http.StatusBadRequest, 400,
				"the requested time is not an NTP timestamp")
			return
		}
		seconds := int64(raw >> 32)
		number = (seconds - s.domain.Period.OffsetSeconds) / s.domain.Period.LengthSeconds
	}

	keySet, err := s.domain.KeySetForPeriod(target, number)
	if err != nil {
		s.respondError(w, r, identity, req, http.StatusInternalServerError, 500, err.Error())
		return
	}
	s.write(w, r, identity, req, &KmsMessage{
		KeyProv: &KmsKeyProv{Version: messageVer, KeySets: []KmsKeySet{*keySet}},
	})
}

// mayProvision decides whether the authenticated client may ask for key
// material bound to another identity. A user may provision their own
// identities; the group management server identity is provisioned for
// the server itself (clause 5.7.1), which is configured explicitly.
func (s *Server) mayProvision(identity, requested string) bool {
	if strings.EqualFold(identity, requested) {
		return true
	}
	for _, allowed := range s.cfg.KMS.ServerIdentities {
		if strings.EqualFold(identity, allowed) {
			return true
		}
	}
	return false
}

// respondCertCache answers a CertCache request with the certificates of
// external security domains, alongside this domain's own (clause 5.3.4).
func (s *Server) respondCertCache(w http.ResponseWriter, r *http.Request, identity string, req *KmsRequest, rest []string) {
	cert, err := s.domain.Certificate()
	if err != nil {
		s.respondError(w, r, identity, req, http.StatusInternalServerError, 500, err.Error())
		return
	}
	cache := &KmsCertCache{
		Version:      messageVer,
		CacheNum:     s.cacheNumber(),
		Certificates: append([]KmsCertificate{*cert}, s.external...),
	}
	// A client that already holds this version of the cache is told so
	// by an empty cache rather than a repeat of what it has.
	if len(rest) > 0 && rest[0] != "" {
		if held, err := strconv.Atoi(rest[0]); err == nil && held >= cache.CacheNum {
			cache.Certificates = nil
		}
	}
	s.write(w, r, identity, req, &KmsMessage{CertCache: cache})
}

// respondCert answers a Cert request for one KMS URI (clause D.2.6).
func (s *Server) respondCert(w http.ResponseWriter, r *http.Request, identity string, req *KmsRequest, rest []string) {
	if len(rest) == 0 || rest[0] == "" {
		s.respondError(w, r, identity, req, http.StatusBadRequest, 400, "no KMS URI was requested")
		return
	}
	requested, err := url.PathUnescape(rest[0])
	if err != nil {
		s.respondError(w, r, identity, req, http.StatusBadRequest, 400,
			"the requested KMS URI is not valid")
		return
	}

	if strings.EqualFold(requested, s.domain.KMSURI) {
		cert, err := s.domain.Certificate()
		if err != nil {
			s.respondError(w, r, identity, req, http.StatusInternalServerError, 500, err.Error())
			return
		}
		s.write(w, r, identity, req, &KmsMessage{CertCache: &KmsCertCache{
			Version: messageVer, Certificates: []KmsCertificate{*cert},
		}})
		return
	}
	for _, cert := range s.external {
		if strings.EqualFold(cert.KMSURI, requested) {
			s.write(w, r, identity, req, &KmsMessage{CertCache: &KmsCertCache{
				Version: messageVer, Certificates: []KmsCertificate{cert},
			}})
			return
		}
	}
	// Clause D.3.1: "If the requested KMS Certificate is not available,
	// then an error message is returned."
	s.respondError(w, r, identity, req, http.StatusNotFound, 404,
		"no certificate is held for "+requested)
}

// cacheNumber versions the certificate cache. It changes whenever the set
// of served certificates changes, which is all a client needs to decide
// whether its copy is current.
func (s *Server) cacheNumber() int { return 1 + len(s.external) }

func (s *Server) write(w http.ResponseWriter, r *http.Request, identity string, req *KmsRequest, msg *KmsMessage) {
	s.encode(w, r, identity, req, http.StatusOK, msg, nil)
}

func (s *Server) respondError(w http.ResponseWriter, r *http.Request, identity string, req *KmsRequest, status, code int, message string) {
	s.encode(w, r, identity, req, status, nil, &KmsError{Code: code, Message: message})
}

func (s *Server) encode(w http.ResponseWriter, r *http.Request, identity string, req *KmsRequest, status int, msg *KmsMessage, kmsErr *KmsError) {
	clientReqURL := r.URL.Path
	if req != nil && req.ClientReqURL != "" {
		clientReqURL = req.ClientReqURL
	}
	resp := &KmsResponse{
		Version:      responseVer,
		UserURI:      identity,
		KMSURI:       s.domain.KMSURI,
		Time:         xsdDateTime(time.Now()),
		KMSID:        s.cfg.KMS.KMSID,
		ClientReqURL: clientReqURL,
		Message:      msg,
		Error:        kmsErr,
	}
	body, err := resp.Marshal()
	if err != nil {
		slog.Error("KMS response encoding failed", "err", err)
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	// Key material must not be retained by an intermediary.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		slog.Warn("KMS response write failed", "err", err)
	}
}

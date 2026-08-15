package kms

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
)

const testIdentity = "sip:user@example.test"

func kmsFixture(t *testing.T) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.KMS = config.KMSConfig{
		Enabled:          true,
		KMSURI:           "kms.example.test",
		CertURI:          "cert1.kms.example.test",
		Issuer:           "www.example.test",
		KMSID:            "VectorCoreKMS",
		KeyMaterialFile:  filepath.Join(t.TempDir(), "domain-keys.txt"),
		KeyPeriodSeconds: 2592000,
		ServerIdentities: []string{"sip:gms@example.test"},
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// post drives the interface with an asserted identity, which is the
// trusted-proxy deployment of figure 5.3.3-1.
func post(t *testing.T, s *Server, path, body, identity string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if identity != "" {
		req.Header.Set("X-3GPP-Asserted-Identity", identity)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func decodeResponse(t *testing.T, rr *httptest.ResponseRecorder) *KmsResponse {
	t.Helper()
	resp := &KmsResponse{}
	if err := xml.Unmarshal(rr.Body.Bytes(), resp); err != nil {
		t.Fatalf("response is not valid XML: %v\n%s", err, rr.Body.String())
	}
	return resp
}

// Clause D.2.3: a POST to the "init" subdirectory returns the domain's
// root certificate, carrying the public keys of clause 5.3.5.
func TestInitReturnsRootCertificate(t *testing.T) {
	s := kmsFixture(t)
	rr := post(t, s, RootPath+"/init", "", testIdentity)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	resp := decodeResponse(t, rr)
	if resp.UserURI != testIdentity || resp.KMSURI != "kms.example.test" {
		t.Fatalf("response addressed to %q from %q", resp.UserURI, resp.KMSURI)
	}
	if resp.Message == nil || resp.Message.Init == nil {
		t.Fatalf("no KmsInit in the response:\n%s", rr.Body.String())
	}
	cert := resp.Message.Init.Certificate
	if cert.Role != "Root" {
		t.Fatalf("Role = %q, want Root", cert.Role)
	}
	if cert.UserIDFormat != "2" {
		t.Fatalf("UserIdFormat = %q, want 2 (the clause F.2.1 mechanism)", cert.UserIDFormat)
	}
	if cert.ParameterSet != ParameterSet1 {
		t.Fatalf("ParameterSet = %d, want %d", cert.ParameterSet, ParameterSet1)
	}
	if cert.UserKeyPeriod != 2592000 {
		t.Fatalf("UserKeyPeriod = %d", cert.UserKeyPeriod)
	}

	// PubEncKey is Z_T, an uncompressed point of the 1024-bit SAKKE
	// curve; PubAuthKey is KPAK, an uncompressed P-256 point.
	enc, err := hex.DecodeString(cert.PubEncKey)
	if err != nil || len(enc) != 1+2*sakkeOctets {
		t.Fatalf("PubEncKey is %d octets (err %v), want %d", len(enc), err, 1+2*sakkeOctets)
	}
	if _, err := unmarshalPoint(enc); err != nil {
		t.Fatalf("PubEncKey is not a point of the SAKKE curve: %v", err)
	}
	auth, err := hex.DecodeString(cert.PubAuthKey)
	if err != nil || len(auth) != 1+2*eccsiOctets {
		t.Fatalf("PubAuthKey is %d octets (err %v), want %d", len(auth), err, 1+2*eccsiOctets)
	}
}

// Clause D.2.4: a POST to "keyprov" returns a key set whose material
// verifies against the certificate the same client was initialised with.
func TestKeyProvIssuesVerifiableKeyMaterial(t *testing.T) {
	s := kmsFixture(t)
	rr := post(t, s, RootPath+"/keyprov", "", testIdentity)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rr.Code, rr.Body.String())
	}
	resp := decodeResponse(t, rr)
	if resp.Message == nil || resp.Message.KeyProv == nil || len(resp.Message.KeyProv.KeySets) != 1 {
		t.Fatalf("no key set in the response:\n%s", rr.Body.String())
	}

	set := resp.Message.KeyProv.KeySets[0]
	if set.UserURI != testIdentity {
		t.Fatalf("key set issued for %q", set.UserURI)
	}
	if set.CertURI != "cert1.kms.example.test" {
		t.Fatalf("CertUri = %q", set.CertURI)
	}
	// UserID is the base64 encoded UID of clause F.2.1, and it must be
	// the UID the server would derive for this identity and period.
	uid, err := base64.StdEncoding.DecodeString(set.UserID)
	if err != nil || len(uid) != 32 {
		t.Fatalf("UserID is not a base64 256-bit UID: %v", err)
	}
	want, err := UID(testIdentity, "kms.example.test",
		KeyPeriod{LengthSeconds: 2592000}, set.KeyPeriodNo)
	if err != nil {
		t.Fatal(err)
	}
	if string(uid) != string(want) {
		t.Fatalf("UserID does not match the derived UID for period %d", set.KeyPeriodNo)
	}

	rsk, err := hex.DecodeString(set.DecryptKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.domain.sakke.ValidateReceiverSecretKey(uid, rsk); err != nil {
		t.Fatalf("UserDecryptKey does not verify: %v", err)
	}

	ssk, err := hex.DecodeString(set.SigningKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	pvt, err := hex.DecodeString(set.PubToken.Value)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.domain.eccsi.ValidateSigningKey(uid, &SigningKey{SSK: ssk, PVT: pvt}); err != nil {
		t.Fatalf("UserSigningKeySSK does not verify against KPAK: %v", err)
	}
}

// Clause D.2.4 example 2: the request URI may name an identity and an
// NTP timestamp, and the key set comes back for that key period.
func TestKeyProvHonoursRequestedIdentityAndTime(t *testing.T) {
	s := kmsFixture(t)

	// D6B4323200000000 is 23 Feb 2014 08:39:14 UTC on the NTP timescale.
	rr := post(t, s, RootPath+"/keyprov/sip%3Auser%40example.test/D6B4323200000000", "", testIdentity)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rr.Code, rr.Body.String())
	}
	set := decodeResponse(t, rr).Message.KeyProv.KeySets[0]

	period := KeyPeriod{LengthSeconds: 2592000}
	want := period.Number(time.Date(2014, 2, 23, 8, 39, 14, 0, time.UTC))
	if set.KeyPeriodNo != want {
		t.Fatalf("KeyPeriodNo = %d, want %d", set.KeyPeriodNo, want)
	}
	from, to := period.Bounds(want)
	if set.ValidFrom != xsdDateTime(from) || set.ValidTo != xsdDateTime(to.Add(-time.Second)) {
		t.Fatalf("validity %s..%s does not bracket key period %d",
			set.ValidFrom, set.ValidTo, want)
	}
}

// A client must not be able to obtain another user's key material: the
// authenticated identity, not the request, decides whose keys are
// derived.
func TestKeyProvRefusesAnotherIdentity(t *testing.T) {
	s := kmsFixture(t)
	rr := post(t, s, RootPath+"/keyprov/sip%3Avictim%40example.test", "", testIdentity)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rr.Code, rr.Body.String())
	}

	// A configured server identity is the documented exception: a group
	// management server is provisioned for its own URI (clause 5.7.1).
	rr = post(t, s, RootPath+"/keyprov/sip%3Auser%40example.test", "", "sip:gms@example.test")
	if rr.Code != http.StatusOK {
		t.Fatalf("server identity refused: %d %s", rr.Code, rr.Body.String())
	}
}

// A request with no access token and no asserted identity is refused:
// clause 5.3.3 step 1 has no unauthenticated case.
func TestUnauthenticatedRequestIsRefused(t *testing.T) {
	s := kmsFixture(t)
	if rr := post(t, s, RootPath+"/init", "", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

// Clause D.2.1: requests are POSTs. Anything else is refused.
func TestNonPostIsRefused(t *testing.T) {
	s := kmsFixture(t)
	req := httptest.NewRequest(http.MethodGet, RootPath+"/init", nil)
	req.Header.Set("X-3GPP-Asserted-Identity", testIdentity)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

// Clause D.2.2: a KmsRequest payload is checked before it is acted on.
// The KmsUri must be this KMS, the ClientReqUrl must match the resource
// the POST went to, the Time must be recent, and the UserUri must be the
// authenticated user.
func TestRequestPayloadChecks(t *testing.T) {
	s := kmsFixture(t)
	request := func(userURI, kmsURI, reqURL, when string) string {
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
			`<KmsRequest xmlns="urn:3gpp:ns:mcsecKMSInterface:1.0" Version="1.1.0">`+
			`<UserUri>%s</UserUri><KmsUri>%s</KmsUri><Time>%s</Time>`+
			`<ClientReqUrl>%s</ClientReqUrl></KmsRequest>`,
			userURI, kmsURI, when, reqURL)
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05")
	url := "https://kms.example.test" + RootPath + "/init"

	body := request(testIdentity, "kms.example.test", url, now)
	if rr := post(t, s, RootPath+"/init", body, testIdentity); rr.Code != http.StatusOK {
		t.Fatalf("a well-formed request was refused: %d %s", rr.Code, rr.Body.String())
	}

	for name, body := range map[string]string{
		"wrong KMS":      request(testIdentity, "kms.elsewhere.test", url, now),
		"wrong resource": request(testIdentity, "kms.example.test", "https://kms.example.test"+RootPath+"/keyprov", now),
		"stale time":     request(testIdentity, "kms.example.test", url, "2014-01-26T10:05:52"),
		"other user":     request("sip:victim@example.test", "kms.example.test", url, now),
	} {
		if rr := post(t, s, RootPath+"/init", body, testIdentity); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", name, rr.Code)
		}
	}
}

// Clause D.2.5: the CertCache request serves the domain's certificates,
// and a client that already holds the current cache is not sent it again.
func TestCertCache(t *testing.T) {
	s := kmsFixture(t)
	rr := post(t, s, RootPath+"/certcache", "", testIdentity)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	cache := decodeResponse(t, rr).Message.CertCache
	if len(cache.Certificates) != 1 || cache.Certificates[0].KMSURI != "kms.example.test" {
		t.Fatalf("unexpected cache contents: %+v", cache.Certificates)
	}

	held := fmt.Sprintf("%s/certcache/%d", RootPath, cache.CacheNum)
	rr = post(t, s, held, "", testIdentity)
	if got := decodeResponse(t, rr).Message.CertCache.Certificates; len(got) != 0 {
		t.Fatalf("a current cache was re-sent: %+v", got)
	}
}

// Clause D.2.6 / D.3.1: a Cert request for a KMS the server does not hold
// a certificate for returns an error message rather than an empty cache.
func TestCertRequest(t *testing.T) {
	s := kmsFixture(t)
	rr := post(t, s, RootPath+"/cert/kms.example.test", "", testIdentity)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if certs := decodeResponse(t, rr).Message.CertCache.Certificates; len(certs) != 1 {
		t.Fatalf("expected one certificate, got %d", len(certs))
	}

	rr = post(t, s, RootPath+"/cert/kms.unknown.test", "", testIdentity)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	resp := decodeResponse(t, rr)
	if resp.Error == nil || resp.Message != nil {
		t.Fatalf("expected a KmsError and no KmsMessage:\n%s", rr.Body.String())
	}
}

// An unimplemented request type is answered with a KmsError rather than a
// bare HTTP error, so a client sees a response it can parse.
func TestUnknownRequestTypeReturnsKmsError(t *testing.T) {
	s := kmsFixture(t)
	rr := post(t, s, RootPath+"/lookup/sip%3Auser%40example.test", "", testIdentity)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if decodeResponse(t, rr).Error == nil {
		t.Fatalf("no KmsError:\n%s", rr.Body.String())
	}
}

// The domain's master secrets survive a restart: reloading the same key
// material file reproduces the same certificate and the same key sets,
// which is what stops a restart from orphaning provisioned clients.
func TestDomainKeyMaterialIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain-keys.txt")
	spec := Domain{KMSURI: "kms.example.test", Period: KeyPeriod{LengthSeconds: 2592000}}

	first, err := LoadDomain(path, spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadDomain(path, spec)
	if err != nil {
		t.Fatal(err)
	}

	certA, err := first.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	certB, err := second.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if certA.PubEncKey != certB.PubEncKey || certA.PubAuthKey != certB.PubAuthKey {
		t.Fatal("reloading the key material produced a different certificate")
	}

	setA, err := first.KeySetForPeriod(testIdentity, 1514)
	if err != nil {
		t.Fatal(err)
	}
	setB, err := second.KeySetForPeriod(testIdentity, 1514)
	if err != nil {
		t.Fatal(err)
	}
	if setA.DecryptKey.Value != setB.DecryptKey.Value {
		t.Fatal("the same identity and key period produced a different decryption key")
	}
	if setA.UserID != setB.UserID {
		t.Fatal("the same identity and key period produced a different UID")
	}
}

// Key material that anyone but its owner can read is refused rather than
// used: it derives every user key in the domain.
func TestWorldReadableKeyMaterialIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not carry POSIX permission bits")
	}
	path := filepath.Join(t.TempDir(), "domain-keys.txt")
	spec := Domain{KMSURI: "kms.example.test", Period: KeyPeriod{LengthSeconds: 2592000}}
	if _, err := LoadDomain(path, spec); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Skipf("cannot change permissions here: %v", err)
	}
	if _, err := LoadDomain(path, spec); err == nil {
		t.Skip("the filesystem does not report POSIX permission bits")
	} else if !strings.Contains(err.Error(), "readable beyond its owner") {
		t.Fatalf("unexpected error: %v", err)
	}
}

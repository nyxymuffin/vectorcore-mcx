package sip

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/kms"
)

const (
	cskServerIdentity = "sip:mcptt-server@example.test"
	cskClientIdentity = "sip:driver@example.test"
)

// cskFixture provisions a server and a client from one security domain,
// which is the single-domain deployment of TS 33.180 clause 9.2.1.3.
type cskFixture struct {
	domain    *kms.Domain
	server    *Server
	client    *kms.Signer
	clientUID []byte
	serverUID []byte
	kmsPublic []byte
}

func newCSKFixture(t *testing.T) *cskFixture {
	t.Helper()
	domain, err := kms.LoadDomain(t.TempDir()+"/keys.txt", kms.Domain{
		KMSURI:  "kms.example.test",
		CertURI: "cert1.kms.example.test",
		Period:  kms.KeyPeriod{LengthSeconds: 2592000},
	})
	if err != nil {
		t.Fatal(err)
	}

	km, err := serverKeyMaterial(domain, cskServerIdentity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{cskKeys: newCSKStore(), keyMgmt: km}

	// The client's signing material comes from the same KMS.
	clientUID, _, err := kms.UIDAt(cskClientIdentity, domain.KMSURI, domain.Period, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	set, err := domain.KeySet(cskClientIdentity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ssk, err := kms.DecodeKeyContent(set.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	pvt, err := kms.DecodeKeyContent(set.PubToken)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := domain.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	kpak, err := kms.DecodeHex(cert.PubAuthKey)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := kms.DecodeHex(cert.PubEncKey)
	if err != nil {
		t.Fatal(err)
	}

	return &cskFixture{
		domain:    domain,
		server:    srv,
		client:    &kms.Signer{KPAK: kpak, ID: clientUID, Key: &kms.SigningKey{SSK: ssk, PVT: pvt}},
		clientUID: clientUID,
		serverUID: km.uid,
		kmsPublic: enc,
	}
}

// upload builds the MIKEY-SAKKE I_MESSAGE a client attaches to its
// REGISTER, encapsulating csk to the server's identity.
func (f *cskFixture) upload(t *testing.T, csk []byte, csbID uint32) []byte {
	t.Helper()
	m, err := kms.NewIMessage(csbID, csk, f.serverUID, f.kmsPublic)
	if err != nil {
		t.Fatal(err)
	}
	m.InitiatorURI = cskClientIdentity
	m.ResponderURI = cskServerIdentity
	m.InitiatorKMSURI = f.domain.KMSURI
	m.ResponderKMSURI = f.domain.KMSURI
	if err := m.Sign(f.client); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// cskKeyID builds a key identifier with the CSK purpose tag of Annex G
// table G-1 in its four most significant bits.
func cskKeyID(t *testing.T) uint32 {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return cskPurposeTag<<28 | binary.BigEndian.Uint32(b[:])&0x0fffffff
}

// registerWithMikey builds a REGISTER carrying the payload as an
// application/mikey body part.
func registerWithMikey(mikey []byte) *Message {
	body := "--b1\r\nContent-Type: application/mikey\r\n\r\n" + string(mikey) + "\r\n--b1--\r\n"
	raw := "REGISTER sip:mcptt-server@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP client.example.test;branch=z9hG4bK-csk\r\n" +
		"From: <" + cskClientIdentity + ">;tag=1\r\n" +
		"To: <" + cskClientIdentity + ">\r\n" +
		"Call-ID: csk-upload\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Content-Type: multipart/mixed;boundary=\"b1\"\r\n\r\n" + body
	msg, err := Parse([]byte(raw))
	if err != nil {
		panic(err)
	}
	return msg
}

// The whole clause 9.2.1.3 procedure: the client encapsulates a CSK to
// the server's identity, attaches it to a REGISTER, and the server
// recovers exactly that key and binds it to the user.
func TestCSKUploadRecoversTheKey(t *testing.T) {
	f := newCSKFixture(t)
	csk := make([]byte, 16)
	if _, err := rand.Read(csk); err != nil {
		t.Fatal(err)
	}
	keyID := cskKeyID(t)

	msg := registerWithMikey(f.upload(t, csk, keyID))
	if !f.server.handleCSKUpload(msg, cskClientIdentity) {
		t.Fatal("the upload was not accepted")
	}

	got, ok := f.server.cskKeys.Get(cskClientIdentity)
	if !ok {
		t.Fatal("no key was bound to the user")
	}
	if string(got.Key) != string(csk) {
		t.Fatalf("recovered %X, want %X", got.Key, csk)
	}
	if got.KeyID != keyID {
		t.Fatalf("CSK-ID = %#x, want %#x", got.KeyID, keyID)
	}
	// Clause 9.2.1.2: the CSK is 128 bits.
	if len(got.Key) != 16 {
		t.Fatalf("the CSK is %d octets, want 16", len(got.Key))
	}

	// Clause 9.2.1.2: de-registration ends the security context.
	f.server.cskKeys.forget(cskClientIdentity)
	if _, ok := f.server.cskKeys.Get(cskClientIdentity); ok {
		t.Fatal("the key survived de-registration")
	}
}

// A payload whose initiator is not the party that sent the SIP request
// is refused: otherwise a third party's key would be bound to this user.
func TestCSKUploadRefusesMismatchedInitiator(t *testing.T) {
	f := newCSKFixture(t)
	csk := make([]byte, 16)
	if _, err := rand.Read(csk); err != nil {
		t.Fatal(err)
	}

	msg := registerWithMikey(f.upload(t, csk, cskKeyID(t)))
	if f.server.handleCSKUpload(msg, "sip:someone-else@example.test") {
		t.Fatal("a key was accepted for the wrong identity")
	}
	if _, ok := f.server.cskKeys.Get("sip:someone-else@example.test"); ok {
		t.Fatal("a key was bound despite the mismatch")
	}
}

// A key identifier without the CSK purpose tag is not a CSK upload
// (Annex G table G-1), and a tampered payload fails the signature check.
func TestCSKUploadChecksPurposeAndSignature(t *testing.T) {
	f := newCSKFixture(t)
	csk := make([]byte, 16)
	if _, err := rand.Read(csk); err != nil {
		t.Fatal(err)
	}

	// Purpose tag 0 is a GMK, not a CSK.
	gmkID := uint32(0)<<28 | 0x0badf00d
	if f.server.handleCSKUpload(registerWithMikey(f.upload(t, csk, gmkID)), cskClientIdentity) {
		t.Fatal("a key with the wrong purpose tag was accepted as a CSK")
	}

	// A flipped bit anywhere breaks the signature over the message.
	raw := f.upload(t, csk, cskKeyID(t))
	raw[len(raw)/2] ^= 0x01
	if f.server.handleCSKUpload(registerWithMikey(raw), cskClientIdentity) {
		t.Fatal("a tampered payload was accepted")
	}
}

// A server holding no key material ignores uploads rather than failing
// the registration: the CSK is optional application-layer protection.
func TestCSKUploadIgnoredWithoutServerKeys(t *testing.T) {
	f := newCSKFixture(t)
	csk := make([]byte, 16)
	if _, err := rand.Read(csk); err != nil {
		t.Fatal(err)
	}
	raw := f.upload(t, csk, cskKeyID(t))

	bare := &Server{cskKeys: newCSKStore()}
	if bare.handleCSKUpload(registerWithMikey(raw), cskClientIdentity) {
		t.Fatal("a server with no key material accepted an upload")
	}
}

// A request with no MIKEY body part is not an upload, and must not be
// mistaken for a failed one.
func TestNoMikeyBodyIsNotAnUpload(t *testing.T) {
	f := newCSKFixture(t)
	raw := "REGISTER sip:mcptt-server@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP client.example.test;branch=z9hG4bK-plain\r\n" +
		"From: <" + cskClientIdentity + ">;tag=1\r\n" +
		"To: <" + cskClientIdentity + ">\r\n" +
		"Call-ID: plain\r\nCSeq: 1 REGISTER\r\n\r\n"
	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if f.server.handleCSKUpload(msg, cskClientIdentity) {
		t.Fatal("a request with no MIKEY part was treated as an upload")
	}
}

// The key is addressed to the server's UID, so a payload naming a
// different responder is refused before any decapsulation is attempted.
func TestCSKUploadRefusesWrongResponder(t *testing.T) {
	f := newCSKFixture(t)
	csk := make([]byte, 16)
	if _, err := rand.Read(csk); err != nil {
		t.Fatal(err)
	}

	m, err := kms.NewIMessage(cskKeyID(t), csk, f.serverUID, f.kmsPublic)
	if err != nil {
		t.Fatal(err)
	}
	m.InitiatorURI = cskClientIdentity
	m.ResponderURI = "sip:other-server@example.test"
	m.InitiatorKMSURI = f.domain.KMSURI
	m.ResponderKMSURI = f.domain.KMSURI
	if err := m.Sign(f.client); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.server.extractCSK(raw, cskClientIdentity); err == nil ||
		!strings.Contains(err.Error(), "addressed to") {
		t.Fatalf("unexpected result for a misaddressed key: %v", err)
	}
}

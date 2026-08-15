package kms

import (
	"math/big"
	"testing"
	"time"
)

// mikeyFixture provisions a sender and a recipient from one domain: the
// sender gets ECCSI signing material, the recipient a SAKKE decryption
// key, both bound to the UIDs of clause F.2.1.
type mikeyFixture struct {
	domain    *Domain
	sender    *Signer
	senderUID []byte
	recipUID  []byte
	recipRSK  []byte
	kmsPublic []byte
}

func newMikeyFixture(t *testing.T) *mikeyFixture {
	t.Helper()
	d, err := LoadDomain(t.TempDir()+"/keys.txt", Domain{
		KMSURI:  "kms.example.test",
		CertURI: "cert1.kms.example.test",
		Period:  KeyPeriod{LengthSeconds: 2592000},
	})
	if err != nil {
		t.Fatal(err)
	}

	senderUID, _, err := UIDAt("sip:dispatch@example.test", d.KMSURI, d.Period, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recipUID, _, err := UIDAt("sip:driver@example.test", d.KMSURI, d.Period, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	signing, err := d.eccsi.NewSigningKey(senderUID)
	if err != nil {
		t.Fatal(err)
	}
	rsk, err := d.sakke.ReceiverSecretKey(recipUID)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := d.sakke.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	return &mikeyFixture{
		domain:    d,
		sender:    &Signer{KPAK: d.eccsi.Public, ID: senderUID, Key: signing},
		senderUID: senderUID,
		recipUID:  recipUID,
		recipRSK:  rsk,
		kmsPublic: pub,
	}
}

func (f *mikeyFixture) message(t *testing.T, ssv []byte) *IMessage {
	t.Helper()
	m, err := NewIMessage(0x0A0B0C0D, ssv, f.recipUID, f.kmsPublic)
	if err != nil {
		t.Fatal(err)
	}
	m.InitiatorURI = "sip:dispatch@example.test"
	m.ResponderURI = "sip:driver@example.test"
	m.InitiatorKMSURI = f.domain.KMSURI
	m.ResponderKMSURI = f.domain.KMSURI
	return m
}

// An I_MESSAGE round trips: it encodes, parses back to the same fields,
// verifies under the sender's UID, and yields the key it carried.
func TestIMessageRoundTrip(t *testing.T) {
	f := newMikeyFixture(t)
	ssv, err := GenerateSSV()
	if err != nil {
		t.Fatal(err)
	}
	m := f.message(t, ssv)
	if err := m.Sign(f.sender); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Clause E.1.2: data type 26, V bit 0, TS type NTP-UTC.
	if raw[0] != mikeyVersion || raw[1] != dataTypeSAKKE {
		t.Fatalf("header = %#x %#x", raw[0], raw[1])
	}
	if raw[3]&0x80 != 0 {
		t.Fatal("the V bit is set; clause E.1.2 requires 0")
	}

	parsed, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.CSBID != 0x0A0B0C0D {
		t.Fatalf("CSB ID = %#x", parsed.CSBID)
	}
	if parsed.InitiatorURI != "sip:dispatch@example.test" ||
		parsed.ResponderURI != "sip:driver@example.test" {
		t.Fatalf("identities = %q, %q", parsed.InitiatorURI, parsed.ResponderURI)
	}
	if parsed.InitiatorKMSURI != f.domain.KMSURI || parsed.ResponderKMSURI != f.domain.KMSURI {
		t.Fatalf("KMS identities = %q, %q", parsed.InitiatorKMSURI, parsed.ResponderKMSURI)
	}
	if string(parsed.RAND) != string(m.RAND) {
		t.Fatal("the RAND payload did not survive the round trip")
	}
	if drift := parsed.Timestamp.Sub(m.Timestamp); drift > time.Second || drift < -time.Second {
		t.Fatalf("timestamp drifted by %s", drift)
	}

	if err := Verify(raw, f.domain.eccsi.Public, f.senderUID); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}

	got, err := Decapsulate(parsed.SAKKE, f.recipUID, f.recipRSK, f.kmsPublic)
	if err != nil {
		t.Fatalf("the recipient could not recover the key: %v", err)
	}
	if string(got) != string(ssv) {
		t.Fatalf("recovered %X, want %X", got, ssv)
	}
}

// Any change to the message breaks the signature, which is the point of
// signing the whole thing rather than a digest of parts of it.
func TestIMessageSignatureCoversTheWholeMessage(t *testing.T) {
	f := newMikeyFixture(t)
	ssv, err := GenerateSSV()
	if err != nil {
		t.Fatal(err)
	}
	m := f.message(t, ssv)
	if err := m.Sign(f.sender); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Flip a bit in the CSB ID, in an identity and in the SAKKE data.
	for _, offset := range []int{5, len(raw) / 2, len(raw) - signatureLength - 4} {
		tampered := append([]byte{}, raw...)
		tampered[offset] ^= 0x01
		if err := Verify(tampered, f.domain.eccsi.Public, f.senderUID); err == nil {
			t.Fatalf("a change at offset %d went undetected", offset)
		}
	}

	// And a signature from a different signer does not verify.
	other, err := GenerateECCSIKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(raw, other.Public, f.senderUID); err == nil {
		t.Fatal("the message verified under a different KMS root of trust")
	}
}

// A key encapsulated to one recipient cannot be recovered by another,
// which is what makes the SAKKE payload worth carrying.
func TestIMessageKeyIsBoundToTheRecipient(t *testing.T) {
	f := newMikeyFixture(t)
	ssv, err := GenerateSSV()
	if err != nil {
		t.Fatal(err)
	}
	m := f.message(t, ssv)
	if err := m.Sign(f.sender); err != nil {
		t.Fatal(err)
	}

	intruderUID, _, err := UIDAt("sip:intruder@example.test", f.domain.KMSURI, f.domain.Period, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	intruderRSK, err := f.domain.sakke.ReceiverSecretKey(intruderUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decapsulate(m.SAKKE, intruderUID, intruderRSK, f.kmsPublic); err == nil {
		t.Fatal("another user of the same domain recovered the key")
	}
}

// Truncated and malformed messages are refused by the parser rather than
// read past the end of the buffer.
func TestUnmarshalRejectsMalformed(t *testing.T) {
	f := newMikeyFixture(t)
	ssv, err := GenerateSSV()
	if err != nil {
		t.Fatal(err)
	}
	m := f.message(t, ssv)
	if err := m.Sign(f.sender); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range []int{0, 1, 8, 40, len(raw) / 2, len(raw) - 1} {
		if _, err := Unmarshal(raw[:n]); err == nil {
			t.Fatalf("a %d octet prefix parsed as a whole message", n)
		}
	}

	// A message that is not MIKEY-SAKKE at all.
	notSAKKE := append([]byte{}, raw...)
	notSAKKE[1] = 0 // pre-shared key message
	if _, err := Unmarshal(notSAKKE); err == nil {
		t.Fatal("a non-SAKKE data type was accepted")
	}
}

// The CSB ID is what clause E.2.1 uses to carry the GUK-ID, so it must
// survive as an opaque 32-bit value including the top bit.
func TestCSBIDIsOpaque(t *testing.T) {
	f := newMikeyFixture(t)
	ssv, err := GenerateSSV()
	if err != nil {
		t.Fatal(err)
	}
	m := f.message(t, ssv)
	m.CSBID = 0xFFFFFFFF
	if err := m.Sign(f.sender); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.CSBID != 0xFFFFFFFF {
		t.Fatalf("CSB ID = %#x", parsed.CSBID)
	}
}

// The NTP timestamp conversion is the one clause E.1.2 calls for: a
// 64-bit UTC time on the timescale that starts in 1900.
func TestNTPTimestampConversion(t *testing.T) {
	at := time.Date(2014, 1, 26, 10, 7, 14, 0, time.UTC)
	v := ntpTimestamp(at)
	if got := int64(v >> 32); got != 3599719634 {
		t.Fatalf("NTP seconds = %d, want 3599719634", got)
	}
	if got := ntpTime(v); !got.Equal(at) {
		t.Fatalf("round trip gave %s, want %s", got, at)
	}
	// And it is consistent with the key period arithmetic, which shares
	// the epoch.
	if big.NewInt(int64(v>>32)).Int64()-ntpEpochOffset != at.Unix() {
		t.Fatal("the MIKEY and key period epochs disagree")
	}
}

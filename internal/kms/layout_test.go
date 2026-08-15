package kms

import (
	"encoding/binary"
	"testing"
	"time"
)

// A field-by-field walk of an encoded I_MESSAGE against the payload
// diagrams it is built from: RFC 3830 clauses 6.1, 6.5, 6.6 and 6.11,
// RFC 6043 clause 6.6, RFC 6509 clauses 4.1 to 4.4, and the values
// TS 33.180 clause E.1.2 fixes. Unmarshal round trips would still pass if
// both sides shared a mistake, so this checks the bytes directly.
func TestWireLayoutMatchesThePayloadDiagrams(t *testing.T) {
	domain, err := LoadDomain(t.TempDir()+"/keys.txt", Domain{
		KMSURI: "kms.example.test",
		Period: KeyPeriod{LengthSeconds: 2592000},
	})
	if err != nil {
		t.Fatal(err)
	}
	uid, _, err := UIDAt("sip:b@example.test", domain.KMSURI, domain.Period, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := domain.sakke.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ssv, err := GenerateSSV()
	if err != nil {
		t.Fatal(err)
	}

	// A CSB ID carrying the CSK purpose tag of TS 33.180 Annex G in its
	// four most significant bits.
	m, err := NewIMessage(0x21234567, ssv, uid, pub)
	if err != nil {
		t.Fatal(err)
	}
	m.InitiatorURI, m.ResponderURI = "sip:a@example.test", "sip:b@example.test"
	m.InitiatorKMSURI, m.ResponderKMSURI = domain.KMSURI, domain.KMSURI
	signing, err := domain.eccsi.NewSigningKey(uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sign(&Signer{KPAK: domain.eccsi.Public, ID: uid, Key: signing}); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	pos := 0
	take := func(name string, n int) []byte {
		t.Helper()
		if pos+n > len(raw) {
			t.Fatalf("%s runs past the end of the message", name)
		}
		v := raw[pos : pos+n]
		pos += n
		return v
	}
	is := func(name string, got []byte, want ...byte) {
		t.Helper()
		if string(got) != string(want) {
			t.Fatalf("%s = %X, want %X", name, got, want)
		}
	}

	// Common Header, RFC 3830 clause 6.1.
	is("version", take("version", 1), mikeyVersion)
	is("data type", take("data type", 1), dataTypeSAKKE) // RFC 6509 table 1
	is("next payload", take("next payload", 1), payloadT)
	// V is the top bit and must be 0 (clause E.1.2); the remaining seven
	// bits are the PRF, 1 for PRF-HMAC-SHA-256 (RFC 6043 table 6.3).
	is("V and PRF func", take("V|PRF", 1), 0x01)
	is("CSB ID", take("CSB ID", 4), 0x21, 0x23, 0x45, 0x67)
	// Clause E.1.2: CS# 0 with CS ID map type 1, the empty map of
	// RFC 4563 table 3, selects the default security profiles.
	is("#CS", take("#CS", 1), 0)
	is("CS ID map type", take("map type", 1), 1)

	// Timestamp, RFC 3830 clause 6.6.
	is("T next payload", take("T next", 1), payloadRAND)
	is("TS type", take("TS type", 1), tsTypeNTPUTC)
	if got := binary.BigEndian.Uint64(take("TS value", 8)) >> 32; got != uint64(m.Timestamp.Unix()+ntpEpochOffset) {
		t.Fatalf("the timestamp is not the NTP-UTC seconds of the message time")
	}

	// RAND, RFC 3830 clause 6.11: the length "SHOULD be at least 16".
	is("RAND next payload", take("RAND next", 1), payloadIDR)
	randLen := take("RAND len", 1)[0]
	if randLen < 16 {
		t.Fatalf("RAND is %d octets, want at least 16", randLen)
	}
	take("RAND", int(randLen))

	// The four IDR payloads, RFC 6043 clause 6.6 with the KMS roles of
	// RFC 6509 clause 4.4, in the order clause E.1.2 lists them.
	for i, want := range []struct {
		role byte
		uri  string
	}{
		{roleInitiator, "sip:a@example.test"},
		{roleResponder, "sip:b@example.test"},
		{roleKMSi, domain.KMSURI},
		{roleKMSr, domain.KMSURI},
	} {
		next := byte(payloadIDR)
		if i == 3 {
			next = payloadSAKKE
		}
		is("IDR next payload", take("IDR next", 1), next)
		is("IDR role", take("IDR role", 1), want.role)
		is("ID type", take("ID type", 1), idTypeURI) // RFC 3830 table 6.7.a
		n := binary.BigEndian.Uint16(take("IDR len", 2))
		if got := string(take("IDR data", int(n))); got != want.uri {
			t.Fatalf("IDR data = %q, want %q", got, want.uri)
		}
	}

	// SAKKE, RFC 6509 clause 4.2.
	is("SAKKE next payload", take("SAKKE next", 1), payloadSIGN)
	is("SAKKE params", take("params", 1), ParameterSet1)
	// Clause E.1.2: the ID scheme is '3GPP MCX hashed UID', value 2.
	is("ID scheme", take("ID scheme", 1), idSchemeMCXHashedUID)
	sakkeLen := binary.BigEndian.Uint16(take("SAKKE len", 2))
	// RFC 6508 clause 4: the Encapsulated Data is 2*L + n + 1 octets.
	if want := uint16(2*sakkeOctets + ssvBits/8 + 1); sakkeLen != want {
		t.Fatalf("SAKKE data is %d octets, want %d", sakkeLen, want)
	}
	take("SAKKE data", int(sakkeLen))

	// SIGN, RFC 3830 clause 6.5 with the S type of RFC 6509 clause 4.3:
	// four bits of type then twelve of length.
	header := binary.BigEndian.Uint16(take("SIGN header", 2))
	if got := header >> 12; got != sigTypeECCSI {
		t.Fatalf("S type = %d, want %d (ECCSI)", got, sigTypeECCSI)
	}
	if got := int(header & 0x0fff); got != signatureLength {
		t.Fatalf("signature length field = %d, want %d", got, signatureLength)
	}
	if remaining := len(raw) - pos; remaining != signatureLength {
		t.Fatalf("%d octets follow the SIGN header, want %d", remaining, signatureLength)
	}
}

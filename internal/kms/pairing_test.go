package kms

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// The published Encapsulated Data of RFC 6508 Appendix A, for the
// Responder identifier 'b' and the KMS master secret z.
const (
	rfcSSV = "123456789ABCDEF0123456789ABCDEF0"
	rfcR   = "13EE3E1B8DAC5DB168B1CEB32F0566A4" +
		"C273693F78BAFFA2A2EE6A686E6BD90F" +
		"8206CCAB84E7F42ED39BD4FB131012EC" +
		"CA2ECD2119414560C17CAB46B956A80F" +
		"58A3302EB3E2C9A228FBA7ED34D8ACA2" +
		"392DA1FFB0B17B2320AE09AAEDFD0235" +
		"F6FE0EB65337A63F9CC97728B8E5AD04" +
		"60FADE144369AA5B2166213247712096"

	rfcRbx = "44E8AD44AB8592A6A5A3DDCA5CF896C7" +
		"18043606A01D650DEF37A01F37C228C3" +
		"32FC317354E2C274D4DAF8AD001054C7" +
		"6CE57971C6F4486D5723043261C506EB" +
		"F5BE438F53DE04F067C776E0DD3B71A6" +
		"290133283725A532F21AF145126DC1D7" +
		"77ECC27BE50835BD28098B8A73D9F801" +
		"D893793A41FF5C49B87E79F2BE4D56CE"
	rfcRby = "557E134AD85BB1D4B9CE4F8BE4B08A12" +
		"BABF55B1D6F1D7A638019EA28E15AB1C" +
		"9F76375FDD1210D4F4351B9A009486B7" +
		"F3ED46C965DED2D80DADE4F38C6721D5" +
		"2C3AD103A10EBD2959248B4EF006836B" +
		"F097448E6107C9EDEE9FB704823DF199" +
		"F832C905AE45F8A247A072D8EF729EAB" +
		"C5E27574B07739B34BE74A532F747B86"

	rfcGr = "7D2A8438E6291C649B6579EB3B79EAE9" +
		"48B1DE9E5F7D1F4070A08F8DB6B3C515" +
		"6F2201AFFBB5CB9D82AA3EC0D0398B89" +
		"ABC78A13A760C0BF3F77E63D0DF3F1A3" +
		"41A41B8811DF197FD6CD0F003125606F" +
		"4F109F400F7292A10D255E3C0EBCCB42" +
		"53FB182C68F09CF6CD9C4A53DA6C74AD" +
		"007AF36B8BCA979D5895E282F483FCD6"

	rfcMask = "9BD4EA1E801D37E62AD2FAB0D4F5BBF7"
	rfcHint = "89E0BC661AA1E91638E6ACC84E496507"

	rfcKbx = "93AF67E5007BA6E6A80DA793DA300FA4" +
		"B52D0A74E25E6E7B2B3D6EE9D18A9B5C" +
		"5023597BD82D8062D34019563BA1D25C" +
		"0DC56B7B979D74AA50F29FBF11CC2C93" +
		"F5DFCA615E609279F6175CEADB00B58C" +
		"6BEE1E7A2A47C4F0C456F05259A6FA94" +
		"A634A40DAE1DF593D4FECF688D5FC678" +
		"BE7EFC6DF3D6835325B83B2C6E69036B"
	rfcKby = "155F0A27241094B04BFB0BDFAC6C670A" +
		"65C325D39A069F03659D44CA27D3BE8D" +
		"F311172B554160181CBE94A2A783320C" +
		"ED590BC42644702CF371271E496BF20F" +
		"588B78A1BC01ECBB6559934BDD2FB65D" +
		"2884318A33D1A42ADF5E33CC5800280B" +
		"28356497F87135BAB9612A1726042440" +
		"9AC15FEE996B744C332151235DECB0F5"
)

// rfcIdentifier is 'b', the same "2011-02\0tel:+447700900123\0" string
// the ECCSI vector uses.
func rfcIdentifier(t *testing.T) []byte { return hexBytes(t, rfcSignerID) }

func rfcPoint(t *testing.T, x, y string) []byte {
	t.Helper()
	out := []byte{4}
	out = append(out, hexBytes(t, x)...)
	return append(out, hexBytes(t, y)...)
}

// RFC 6508 Appendix A: r = HashToIntegerRange( SSV || b, q, SHA-256 ).
func TestHashToIntegerRangeMatchesRFC6508(t *testing.T) {
	input := append(hexBytes(t, rfcSSV), rfcIdentifier(t)...)
	got := hashToIntegerRange(input, sakkeQ)
	want, ok := new(big.Int).SetString(rfcR, 16)
	if !ok {
		t.Fatal("bad r fixture")
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("r = %X,\nwant %X", got, want)
	}

	// And the mask, which hashes g^r into the SSV range.
	mask := hashToIntegerRange(hexBytes(t, rfcGr), new(big.Int).Lsh(big.NewInt(1), ssvBits))
	if got := strings.ToUpper(hex.EncodeToString(mask.Bytes())); got != rfcMask {
		t.Fatalf("mask = %s, want %s", got, rfcMask)
	}
}

// The published g^r follows from the published r through the PF_p group
// operation, which is not ordinary field exponentiation (clause 6.2.1
// step 4a).
func TestPFpExponentiationMatchesRFC6508(t *testing.T) {
	r, _ := new(big.Int).SetString(rfcR, 16)
	got, err := pfpExp(sakkeG, r)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := new(big.Int).SetString(rfcGr, 16)
	if got.Cmp(want) != 0 {
		t.Fatalf("g^r = %X,\nwant %X", got, want)
	}
}

// The full sender side of clause 6.2.1 reproduces the published
// Encapsulated Data: the point R_(b,S) and the Hint H.
func TestEncapsulateMatchesRFC6508(t *testing.T) {
	z, _ := new(big.Int).SetString("AFF429D35F84B110D094803B3595A6E2998BC99F", 16)
	kp, err := NewSAKKEKeyPair(z)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	enc, err := Encapsulate(hexBytes(t, rfcSSV), rfcIdentifier(t), pub)
	if err != nil {
		t.Fatal(err)
	}
	if want := rfcPoint(t, rfcRbx, rfcRby); string(enc.R) != string(want) {
		t.Fatalf("R_(b,S) = %X,\nwant %X", enc.R, want)
	}
	if want := hexBytes(t, rfcHint); string(enc.H) != string(want) {
		t.Fatalf("H = %X, want %X", enc.H, want)
	}
}

// The pairing itself: < R_(b,S), K_(b,S) > is g^r, which is the whole
// reason the receiver can recover the SSV (clause 6.2.2 step 2).
func TestPairingMatchesRFC6508(t *testing.T) {
	r, err := unmarshalPoint(rfcPoint(t, rfcRbx, rfcRby))
	if err != nil {
		t.Fatal(err)
	}
	k, err := unmarshalPoint(rfcPoint(t, rfcKbx, rfcKby))
	if err != nil {
		t.Fatal(err)
	}

	w, err := pair(r, k)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := new(big.Int).SetString(rfcGr, 16)
	if w.Cmp(want) != 0 {
		t.Fatalf("w = %X,\nwant %X", w, want)
	}
}

// The published RSK is the one this KMS would issue for that identifier
// under the published master secret, which ties the extraction of
// clause 6.1.1 to the exchange vectors.
func TestPublishedRSKIsTheDerivedOne(t *testing.T) {
	z, _ := new(big.Int).SetString("AFF429D35F84B110D094803B3595A6E2998BC99F", 16)
	kp, err := NewSAKKEKeyPair(z)
	if err != nil {
		t.Fatal(err)
	}
	rsk, err := kp.ReceiverSecretKey(rfcIdentifier(t))
	if err != nil {
		t.Fatal(err)
	}
	if want := rfcPoint(t, rfcKbx, rfcKby); string(rsk) != string(want) {
		t.Fatalf("RSK = %X,\nwant %X", rsk, want)
	}
}

// Decapsulation recovers the published SSV from the published
// Encapsulated Data (clause 6.2.2).
func TestDecapsulateMatchesRFC6508(t *testing.T) {
	z, _ := new(big.Int).SetString("AFF429D35F84B110D094803B3595A6E2998BC99F", 16)
	kp, err := NewSAKKEKeyPair(z)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	ssv, err := Decapsulate(&Encapsulation{
		R: rfcPoint(t, rfcRbx, rfcRby),
		H: hexBytes(t, rfcHint),
	}, rfcIdentifier(t), rfcPoint(t, rfcKbx, rfcKby), pub)
	if err != nil {
		t.Fatal(err)
	}
	if want := hexBytes(t, rfcSSV); string(ssv) != string(want) {
		t.Fatalf("SSV = %X, want %X", ssv, want)
	}
}

// A round trip over freshly generated domain key material, with the UID
// derivation of TS 33.180 in the loop, which is how an MC deployment
// actually uses this.
func TestSAKKERoundTripWithMCIdentity(t *testing.T) {
	kp, err := GenerateSAKKEKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := UID("sip:server@example.test", "kms.example.test",
		KeyPeriod{LengthSeconds: 2592000}, 1541)
	if err != nil {
		t.Fatal(err)
	}
	rsk, err := kp.ReceiverSecretKey(uid)
	if err != nil {
		t.Fatal(err)
	}

	ssv, err := GenerateSSV()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Encapsulate(ssv, uid, pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decapsulate(enc, uid, rsk, pub)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(ssv) {
		t.Fatalf("round trip produced %X, want %X", got, ssv)
	}
}

// Clause 6.2.2 step 5 is a check, not a formality: a tampered Hint must
// be refused rather than yielding a silently different SSV.
func TestDecapsulateRejectsTamperedData(t *testing.T) {
	kp, err := GenerateSAKKEKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := UID("sip:server@example.test", "kms.example.test",
		KeyPeriod{LengthSeconds: 2592000}, 1541)
	if err != nil {
		t.Fatal(err)
	}
	rsk, err := kp.ReceiverSecretKey(uid)
	if err != nil {
		t.Fatal(err)
	}
	ssv, err := GenerateSSV()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Encapsulate(ssv, uid, pub)
	if err != nil {
		t.Fatal(err)
	}

	enc.H[0] ^= 0x01
	if _, err := Decapsulate(enc, uid, rsk, pub); err == nil {
		t.Fatal("a tampered Hint was accepted")
	}
}

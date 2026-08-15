package kms

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", ""))
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// The Signer ID of both RFC test vectors: "2011-02\0tel:+447700900123\0".
const rfcSignerID = "32303131" + "2D303200" + "74656C3A" + "2B343437" + "37303039" + "30303132" + "3300"

// RFC 6507 Appendix A: KSAK 0x12345 fixes KPAK.
func TestECCSIKPAKMatchesRFC6507(t *testing.T) {
	kp, err := NewECCSIKeyPair(big.NewInt(0x12345))
	if err != nil {
		t.Fatal(err)
	}
	want := hexBytes(t, "04"+
		"50D4670BDE75244F28D2838A0D25558A"+
		"7A72686D4522D4C8273FB6442AEBFA93"+
		"DBDD37551AFD263B5DFD617F3960C65A"+
		"8C298850FF99F20366DCE7D4367217F4")
	if got := kp.Public; string(got) != string(want) {
		t.Fatalf("KPAK = %X, want %X", got, want)
	}
}

// RFC 6507 Appendix A: with the ephemeral v fixed at 0x23456 the KMS
// produces the published PVT, HS and SSK (clause 5.1.1), and the
// resulting key passes the clause 5.1.2 validation.
func TestECCSISigningKeyMatchesRFC6507(t *testing.T) {
	kp, err := NewECCSIKeyPair(big.NewInt(0x12345))
	if err != nil {
		t.Fatal(err)
	}
	id := hexBytes(t, rfcSignerID)

	key, err := kp.signingKeyWithEphemeral(id, big.NewInt(0x23456))
	if err != nil {
		t.Fatal(err)
	}

	wantPVT := hexBytes(t, "04"+
		"758A142779BE89E829E71984CB40EF75"+
		"8CC4AD775FC5B9A3E1C8ED52F6FA36D9"+
		"A79D247692F4EDA3A6BDAB77D6AA6474"+
		"A464AE4934663C5265BA7018BA091F79")
	if string(key.PVT) != string(wantPVT) {
		t.Fatalf("PVT = %X, want %X", key.PVT, wantPVT)
	}

	wantHS := hexBytes(t, "490F3FEBBC1C902F6289723D7F8CBF79"+
		"DB88930849D19F38F0295B5C276C14D1")
	if string(key.HS) != string(wantHS) {
		t.Fatalf("HS = %X, want %X", key.HS, wantHS)
	}

	wantSSK := hexBytes(t, "23F374AE1F4033F3E9DBDDAAEF20F4CF"+
		"0B86BBD5A138A5AE9E7E006B34489A0D")
	if string(key.SSK) != string(wantSSK) {
		t.Fatalf("SSK = %X, want %X", key.SSK, wantSSK)
	}

	if err := kp.ValidateSigningKey(id, key); err != nil {
		t.Fatalf("published key material fails clause 5.1.2 validation: %v", err)
	}
}

// A randomly generated ECCSI key pair still satisfies the client-side
// check, which is what a provisioned device runs before installing it.
func TestECCSIGeneratedKeyValidates(t *testing.T) {
	kp, err := GenerateECCSIKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	id := []byte("sip:user@example.test")
	key, err := kp.NewSigningKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.ValidateSigningKey(id, key); err != nil {
		t.Fatalf("generated key fails validation: %v", err)
	}
	// A key issued for one identity must not validate under another.
	if err := kp.ValidateSigningKey([]byte("sip:other@example.test"), key); err == nil {
		t.Fatal("key validated under the wrong identity")
	}
}

// RFC 6508 Appendix A: the published master secret z yields the
// published KMS Public Key Z_T = [z]P (clause 6.1). This exercises the
// whole 1024-bit curve implementation.
func TestSAKKEPublicKeyMatchesRFC6508(t *testing.T) {
	z, ok := new(big.Int).SetString("AFF429D35F84B110D094803B3595A6E2998BC99F", 16)
	if !ok {
		t.Fatal("bad master secret fixture")
	}
	kp, err := NewSAKKEKeyPair(z)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	wantX := hexBytes(t, "5958EF1B1679BF099B3A030DF255AA6A"+
		"23C1D8F143D4D23F753E69BD27A832F3"+
		"8CB4AD53DDEF4260B0FE8BB45C4C1FF5"+
		"10EFFE300367A37B61F701D914AEF097"+
		"24825FA0707D61A6DFF4FBD7273566CD"+
		"DE352A0B04B7C16A78309BE640697DE7"+
		"47613A5FC195E8B9F328852A579DB8F9"+
		"9B1D0034479EA9C5595F47C4B2F54FF2")
	wantY := hexBytes(t, "1508D37514DCF7A8E143A6058C09A6BF"+
		"2C9858CA37C258065AE6BF7532BC8B5B"+
		"63383866E0753C5AC0E72709F8445F2E"+
		"6178E065857E0EDA10F68206B63505ED"+
		"87E534FB2831FF957FB7DC619DAE6130"+
		"1EEACC2FDA3680EA4999258A833CEA8F"+
		"C67C6D19487FB449059F26CC8AAB655A"+
		"B58B7CC796E24E9A394095754F5F8BAE")

	if pub[0] != 4 {
		t.Fatalf("Z_T is not in uncompressed form: %#x", pub[0])
	}
	if got := pub[1 : 1+sakkeOctets]; string(got) != string(wantX) {
		t.Fatalf("Zx = %X, want %X", got, wantX)
	}
	if got := pub[1+sakkeOctets:]; string(got) != string(wantY) {
		t.Fatalf("Zy = %X, want %X", got, wantY)
	}
}

// The generator P published in RFC 6509 Appendix A lies on the curve and
// has order q, so [q]P is the point at infinity.
func TestSAKKEGeneratorHasOrderQ(t *testing.T) {
	if !sakkeBase.onCurve() {
		t.Fatal("the published generator is not on the curve")
	}
	pt, err := scalarMult(sakkeQ, sakkeBase)
	if err != nil {
		t.Fatal(err)
	}
	if !pt.isInfinity() {
		t.Fatal("[q]P is not the point at infinity")
	}
}

// An RSK derived per clause 6.1.1 satisfies [a + z]RSK = P, the
// pairing-free form of the clause 6.1.2 receiver check.
func TestSAKKEReceiverSecretKeyVerifies(t *testing.T) {
	kp, err := GenerateSAKKEKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	uid, _, err := UIDAt("sip:user@example.test", "kms.example.test",
		KeyPeriod{LengthSeconds: 2592000}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}

	rsk, err := kp.ReceiverSecretKey(uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.ValidateReceiverSecretKey(uid, rsk); err != nil {
		t.Fatalf("RSK fails verification: %v", err)
	}

	other, _, err := UIDAt("sip:other@example.test", "kms.example.test",
		KeyPeriod{LengthSeconds: 2592000}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.ValidateReceiverSecretKey(other, rsk); err == nil {
		t.Fatal("RSK verified against the wrong identity")
	}
}

// TS 33.180 clause F.2.1.2 works a complete UID example, which pins both
// the parameter encoding and the key period arithmetic.
func TestUIDMatchesTS33180Example(t *testing.T) {
	period := KeyPeriod{LengthSeconds: 2592000, OffsetSeconds: 0}

	// TIME is 3599719634 on the NTP timescale, i.e. 2014-01-26T10:07:14Z.
	at := time.Date(2014, 1, 26, 10, 7, 14, 0, time.UTC)
	if got := at.Unix() + ntpEpochOffset; got != 3599719634 {
		t.Fatalf("NTP time = %d, want 3599719634", got)
	}
	if got := period.Number(at); got != 1388 {
		t.Fatalf("key period number = %d, want 1388", got)
	}

	uid, _, err := UIDAt("sip:user@example.org", "kms.example.org", period, at)
	if err != nil {
		t.Fatal(err)
	}
	const want = "OoH7FMOx0P5DycV3EE1VptgXiL/S8JdDxFV3RqWgNTs="
	if got := base64.StdEncoding.EncodeToString(uid); got != want {
		t.Fatalf("UID = %s, want %s", got, want)
	}
}

// The key period bounds bracket the instant they were derived from and
// are exactly one period apart.
func TestKeyPeriodBounds(t *testing.T) {
	period := KeyPeriod{LengthSeconds: 2592000, OffsetSeconds: 0}
	at := time.Date(2014, 1, 26, 10, 7, 14, 0, time.UTC)
	from, to := period.Bounds(period.Number(at))
	if !from.Before(at) || !to.After(at) {
		t.Fatalf("bounds %s..%s do not contain %s", from, to, at)
	}
	if to.Sub(from) != 2592000*time.Second {
		t.Fatalf("period length = %s, want 2592000s", to.Sub(from))
	}
}

// An offset that is not less than the period length is rejected, as is a
// non-positive length (clause F.2.1.1: "P4 ... shall be less than P3").
func TestKeyPeriodValidation(t *testing.T) {
	for _, p := range []KeyPeriod{
		{LengthSeconds: 0},
		{LengthSeconds: 2592000, OffsetSeconds: 2592000},
		{LengthSeconds: 2592000, OffsetSeconds: -1},
	} {
		if err := p.Validate(); err == nil {
			t.Fatalf("%+v was accepted", p)
		}
	}
}

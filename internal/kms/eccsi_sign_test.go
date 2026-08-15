package kms

import (
	"math/big"
	"testing"
)

// rfcSigner rebuilds the signer of RFC 6507 Appendix A: KSAK 0x12345 with
// the (SSK, PVT) pair produced by ephemeral v = 0x23456.
func rfcSigner(t *testing.T) (*ECCSIKeyPair, *Signer) {
	t.Helper()
	kp, err := NewECCSIKeyPair(big.NewInt(0x12345))
	if err != nil {
		t.Fatal(err)
	}
	id := hexBytes(t, rfcSignerID)
	key, err := kp.signingKeyWithEphemeral(id, big.NewInt(0x23456))
	if err != nil {
		t.Fatal(err)
	}
	return kp, &Signer{KPAK: kp.Public, ID: id, Key: key}
}

// RFC 6507 Appendix A: signing "message\0" with ephemeral j = 0x34567
// produces the published r, s and full signature.
func TestECCSISignMatchesRFC6507(t *testing.T) {
	_, signer := rfcSigner(t)
	message := hexBytes(t, "6D65737361676500") // "message\0"

	sig, err := signer.signWithEphemeral(message, big.NewInt(0x34567))
	if err != nil {
		t.Fatal(err)
	}

	wantR := hexBytes(t, "269D4C8FDEB66A74E4EF8C0D5DCC597D"+
		"DFE6029C2AFFC4936008CD2CC1045D81")
	if got := sig[:eccsiOctets]; string(got) != string(wantR) {
		t.Fatalf("r = %X, want %X", got, wantR)
	}

	wantS := hexBytes(t, "E09B528D0EF8D6DF1AA3ECBF80110CFC"+
		"EC9FC68252CEBB679F4134846940CCFD")
	if got := sig[eccsiOctets : 2*eccsiOctets]; string(got) != string(wantS) {
		t.Fatalf("s = %X, want %X", got, wantS)
	}
	if got := sig[2*eccsiOctets:]; string(got) != string(signer.Key.PVT) {
		t.Fatalf("the signature does not carry the PVT")
	}

	// And the published HE, which the signature is built on.
	wantHE := hexBytes(t, "111F90EAE8271C96DF9B3D6726768D9E"+
		"E9B18145D7EC152CFA9C23D1C4F02285")
	if got := eccsiHE(signer.Key.HS, sig[:eccsiOctets], message); string(got) != string(wantHE) {
		t.Fatalf("HE = %X, want %X", got, wantHE)
	}
}

// The published signature verifies under the published KPAK and
// identifier (clause 5.2.2).
func TestECCSIVerifyMatchesRFC6507(t *testing.T) {
	kp, signer := rfcSigner(t)
	message := hexBytes(t, "6D65737361676500")

	sig := append(append(
		hexBytes(t, "269D4C8FDEB66A74E4EF8C0D5DCC597D"+
			"DFE6029C2AFFC4936008CD2CC1045D81"),
		hexBytes(t, "E09B528D0EF8D6DF1AA3ECBF80110CFC"+
			"EC9FC68252CEBB679F4134846940CCFD")...),
		signer.Key.PVT...)

	if err := VerifySignature(kp.Public, signer.ID, message, sig); err != nil {
		t.Fatalf("the published signature does not verify: %v", err)
	}
}

// A signature with a random ephemeral verifies, and does not verify
// against a different message, a different identifier or a different
// root of trust.
func TestECCSISignRoundTrip(t *testing.T) {
	kp, signer := rfcSigner(t)
	message := []byte("MIKEY-SAKKE I_MESSAGE")

	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(kp.Public, signer.ID, message, sig); err != nil {
		t.Fatalf("a fresh signature does not verify: %v", err)
	}

	if err := VerifySignature(kp.Public, signer.ID, []byte("tampered"), sig); err == nil {
		t.Fatal("the signature verified over a different message")
	}
	if err := VerifySignature(kp.Public, []byte("someone else"), message, sig); err == nil {
		t.Fatal("the signature verified under a different identifier")
	}

	other, err := GenerateECCSIKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(other.Public, signer.ID, message, sig); err == nil {
		t.Fatal("the signature verified under a different KPAK")
	}
}

// A signature of the wrong length, or one carrying a PVT that is not a
// point of the curve, is refused rather than parsed (clause 5.2.2 step 1).
func TestECCSIVerifyRejectsMalformed(t *testing.T) {
	kp, signer := rfcSigner(t)
	message := []byte("MIKEY-SAKKE I_MESSAGE")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifySignature(kp.Public, signer.ID, message, sig[:len(sig)-1]); err == nil {
		t.Fatal("a truncated signature was accepted")
	}
	mangled := append([]byte{}, sig...)
	mangled[2*eccsiOctets+1] ^= 0xff
	if err := VerifySignature(kp.Public, signer.ID, message, mangled); err == nil {
		t.Fatal("a signature with an off-curve PVT was accepted")
	}
}

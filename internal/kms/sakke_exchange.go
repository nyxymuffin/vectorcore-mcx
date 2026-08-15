package kms

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

// SAKKE key exchange, IETF RFC 6508 clause 6.2. This is the half of the
// scheme the MCX entities perform rather than the KMS: a sender
// encapsulates a Shared Secret Value to a recipient's UID, and the
// recipient recovers it with the Receiver Secret Key its KMS issued.
//
// TS 33.180 builds all of its key distribution on this: the CSK a client
// uploads to the MCX Server (clause 5.4), the PCK of a private call
// (clause 5.6) and the GMK a group management server distributes
// (clause 5.7) are each an SSV carried this way inside a MIKEY payload.

// ssvBits is the security parameter n of RFC 6509 Appendix A: the SSVs
// exchanged are 128 bits.
const ssvBits = 128

// sakkeG is g, the element of PF_p[q] published in RFC 6509 Appendix A,
// in the F_p representation of RFC 6508 clause 2.1.
var sakkeG = mustHexInt(
	"66FC2A432B6EA392148F15867D623068" +
		"C6A87BD1FB94C41E27FABE658E015A87" +
		"371E94744C96FEDA449AE9563F8BC446" +
		"CBFDA85D5D00EF577072DA8F541721BE" +
		"EE0FAED1828EAB90B99DFB0138C78433" +
		"55DF0460B4A9FD74B4F1A32BCAFA1FFA" +
		"D682C033A7942BCCE3720F20B9B7B040" +
		"3C8CAE87B7A0042ACDE0FAB36461EA46")

// Encapsulation is the Encapsulated Data of RFC 6508 clause 4: an
// elliptic curve point and an n-bit integer.
type Encapsulation struct {
	// R is R_(b,S), the encoded curve point.
	R []byte
	// H is the Hint, ssvBits/8 octets.
	H []byte
}

// Encapsulate performs the sender steps of RFC 6508 clause 6.2.1: it
// carries ssv to the holder of uid under the KMS public key kmsPublic,
// which is the PubEncKey of that domain's certificate.
//
// ssv must be ssvBits/8 octets. GenerateSSV produces one.
func Encapsulate(ssv, uid, kmsPublic []byte) (*Encapsulation, error) {
	if len(ssv) != ssvBits/8 {
		return nil, fmt.Errorf("the SSV must be %d octets", ssvBits/8)
	}
	zs, err := unmarshalPoint(kmsPublic)
	if err != nil {
		return nil, fmt.Errorf("KMS public key: %w", err)
	}

	// Step 2: r = HashToIntegerRange( SSV || b, q, Hash ).
	r := hashToIntegerRange(append(append([]byte{}, ssv...), uid...), sakkeQ)

	// Step 3: R_(b,S) = [r]( [b]P + Z_S ).
	rPoint, err := recipientPoint(uid, zs, r)
	if err != nil {
		return nil, err
	}
	encoded, err := marshalPoint(rPoint)
	if err != nil {
		return nil, err
	}

	// Step 4: H = SSV XOR HashToIntegerRange( g^r, 2^n, Hash ).
	gr, err := pfpExp(sakkeG, r)
	if err != nil {
		return nil, err
	}
	mask := hashToIntegerRange(fieldOctets(gr), new(big.Int).Lsh(big.NewInt(1), ssvBits))

	hint := make([]byte, ssvBits/8)
	mask.FillBytes(hint)
	subtle.XORBytes(hint, hint, ssv)

	return &Encapsulation{R: encoded, H: hint}, nil
}

// Decapsulate performs the receiver steps of RFC 6508 clause 6.2.2,
// recovering the SSV with the Receiver Secret Key issued for uid. The
// step 5 check is part of the algorithm, not an optional extra: without
// it a tampered encapsulation yields a silently wrong SSV.
func Decapsulate(enc *Encapsulation, uid, rsk, kmsPublic []byte) ([]byte, error) {
	if enc == nil || len(enc.H) != ssvBits/8 {
		return nil, fmt.Errorf("the Hint must be %d octets", ssvBits/8)
	}
	rPoint, err := unmarshalPoint(enc.R)
	if err != nil {
		return nil, fmt.Errorf("encapsulated point: %w", err)
	}
	key, err := unmarshalPoint(rsk)
	if err != nil {
		return nil, fmt.Errorf("receiver secret key: %w", err)
	}
	zs, err := unmarshalPoint(kmsPublic)
	if err != nil {
		return nil, fmt.Errorf("KMS public key: %w", err)
	}

	// Step 2: w = < R_(b,S), K_(b,S) >, which by bilinearity is g^r.
	w, err := pair(rPoint, key)
	if err != nil {
		return nil, err
	}

	// Step 3: SSV = H XOR HashToIntegerRange( w, 2^n, Hash ).
	mask := hashToIntegerRange(fieldOctets(w), new(big.Int).Lsh(big.NewInt(1), ssvBits))
	ssv := make([]byte, ssvBits/8)
	mask.FillBytes(ssv)
	subtle.XORBytes(ssv, ssv, enc.H)

	// Steps 4 and 5: recompute r and check that it reproduces the point
	// that was received.
	r := hashToIntegerRange(append(append([]byte{}, ssv...), uid...), sakkeQ)
	test, err := recipientPoint(uid, zs, r)
	if err != nil {
		return nil, err
	}
	if !test.equal(rPoint) {
		return nil, errors.New("the encapsulated data does not verify; the SSV must not be used")
	}
	return ssv, nil
}

// recipientPoint computes [r]( [b]P + Z_S ), shared by the sender's
// step 3 and the receiver's step 5.
func recipientPoint(uid []byte, zs *point, r *big.Int) (*point, error) {
	b := new(big.Int).SetBytes(uid)
	bp, err := scalarMult(b, sakkeBase)
	if err != nil {
		return nil, err
	}
	sum := bp.add(zs)
	if sum.isInfinity() {
		return nil, errors.New("the recipient identity cancels the KMS public key")
	}
	return scalarMult(r, sum)
}

// fieldOctets renders an element of F_p as the L-octet string that
// RFC 6508 clause 4 requires for hash input.
func fieldOctets(v *big.Int) []byte {
	out := make([]byte, sakkeOctets)
	v.FillBytes(out)
	return out
}

// GenerateSSV produces a random Shared Secret Value of the size SAKKE
// exchanges.
func GenerateSSV() ([]byte, error) {
	ssv := make([]byte, ssvBits/8)
	if _, err := rand.Read(ssv); err != nil {
		return nil, fmt.Errorf("SSV: %w", err)
	}
	return ssv, nil
}

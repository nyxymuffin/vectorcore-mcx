package kms

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// ECCSI signatures, IETF RFC 6507 clause 5.2. These authenticate the
// origin of a MIKEY-SAKKE message: TS 33.180 clause E.1.2 requires every
// such message to carry a SIGN payload of S type '2' (ECCSI) with a
// 32-octet signature computed over the whole message.
//
// Signing needs only the material a KMS provisions - KPAK, the signer's
// identifier, its SSK and its PVT - so it belongs beside the key
// extraction rather than in the KMS server.

// signatureLength is 4N+1 for N = 32: r, s and the uncompressed PVT
// (RFC 6507 clause 3.3).
const signatureLength = 4*eccsiOctets + 1

// Signer holds the per-identity ECCSI material needed to sign.
type Signer struct {
	// KPAK is the KMS Public Authentication Key, the root of trust.
	KPAK []byte
	// ID is the signer's identifier, which for MC use is the UID of
	// TS 33.180 clause F.2.1.
	ID  []byte
	Key *SigningKey
}

// Sign produces the signature ( r || s || PVT ) over message per
// clause 5.2.1.
func (s *Signer) Sign(message []byte) ([]byte, error) {
	order := eccsiCurve().Params().N
	for attempt := 0; attempt < 8; attempt++ {
		j, err := rand.Int(rand.Reader, order)
		if err != nil {
			return nil, fmt.Errorf("ECCSI signature ephemeral: %w", err)
		}
		if j.Sign() == 0 {
			continue
		}
		sig, err := s.signWithEphemeral(message, j)
		if errors.Is(err, errDegenerateEphemeral) {
			continue
		}
		return sig, err
	}
	return nil, errors.New("ECCSI signing did not converge")
}

// signWithEphemeral is the deterministic core of clause 5.2.1, separated
// so the RFC's test vector, which fixes j, can be pinned.
func (s *Signer) signWithEphemeral(message []byte, j *big.Int) ([]byte, error) {
	curve := eccsiCurve()
	order := curve.Params().N

	// Step 2: J = [j]G, and r is the octet string of J's x coordinate.
	jx, _ := curve.ScalarBaseMult(j.Bytes())
	r := make([]byte, eccsiOctets)
	jx.FillBytes(r)

	// Step 3: HE = hash( HS || r || M ).
	hs := s.Key.HS
	if len(hs) == 0 {
		hs = eccsiHS(s.KPAK, s.ID, s.Key.PVT)
	}
	he := eccsiHE(hs, r, message)

	// Step 4: HE + r * SSK must be non-zero modulo q.
	ssk := new(big.Int).SetBytes(s.Key.SSK)
	sum := new(big.Int).Mul(new(big.Int).SetBytes(r), ssk)
	sum.Add(sum, new(big.Int).SetBytes(he))
	sum.Mod(sum, order)
	if sum.Sign() == 0 {
		return nil, errDegenerateEphemeral
	}

	// Step 5: s' = ( (HE + r*SSK)^-1 * j ) mod q.
	inv := new(big.Int).ModInverse(sum, order)
	if inv == nil {
		return nil, errDegenerateEphemeral
	}
	sPrime := inv.Mul(inv, j)
	sPrime.Mod(sPrime, order)

	// Step 6: if s' does not fit in N octets, use q - s' instead. The
	// RFC permits always taking the lesser of the two; taking it only
	// when needed is what reproduces the published vector.
	value := sPrime
	if len(value.Bytes()) > eccsiOctets {
		value = new(big.Int).Sub(order, sPrime)
	}

	// Step 7: Signature = r || s || PVT.
	out := make([]byte, 0, signatureLength)
	out = append(out, r...)
	sOctets := make([]byte, eccsiOctets)
	value.FillBytes(sOctets)
	out = append(out, sOctets...)
	return append(out, s.Key.PVT...), nil
}

// VerifySignature checks a signature against the signer's identifier and
// the root of trust, per clause 5.2.2. The parameter q is not needed.
func VerifySignature(kpak, id, message, signature []byte) error {
	if len(signature) != signatureLength {
		return fmt.Errorf("an ECCSI signature is %d octets", signatureLength)
	}
	curve := eccsiCurve()
	r := signature[:eccsiOctets]
	sOctets := signature[eccsiOctets : 2*eccsiOctets]
	pvt := signature[2*eccsiOctets:]

	// Step 1: PVT must lie on the curve.
	px, py := elliptic.Unmarshal(curve, pvt)
	if px == nil {
		return errors.New("PVT is not a valid point of the curve")
	}

	// Steps 2 and 3.
	hs := eccsiHS(kpak, id, pvt)
	he := eccsiHE(hs, r, message)

	// Step 4: Y = [HS]PVT + KPAK.
	kx, ky := elliptic.Unmarshal(curve, kpak)
	if kx == nil {
		return errors.New("KPAK is not a valid point of the curve")
	}
	hx, hy := curve.ScalarMult(px, py, hs)
	yx, yy := curve.Add(hx, hy, kx, ky)

	// Step 5: J = [s]( [HE]G + [r]Y ).
	ex, ey := curve.ScalarBaseMult(he)
	rx, ry := curve.ScalarMult(yx, yy, r)
	sumX, sumY := curve.Add(ex, ey, rx, ry)
	jx, _ := curve.ScalarMult(sumX, sumY, sOctets)

	// Step 6: Jx must be non-zero and equal to r modulo p.
	jx = new(big.Int).Mod(jx, curve.Params().P)
	if jx.Sign() == 0 {
		return errors.New("the signature reduces to a zero abscissa")
	}
	if jx.Cmp(new(big.Int).Mod(new(big.Int).SetBytes(r), curve.Params().P)) != 0 {
		return errors.New("the signature does not verify")
	}
	return nil
}

// eccsiHS computes hash( G || KPAK || ID || PVT ), the value both the key
// construction of clause 5.1.1 and the signature algorithms depend on.
func eccsiHS(kpak, id, pvt []byte) []byte {
	curve := eccsiCurve()
	digest := sha256.New()
	digest.Write(elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy))
	digest.Write(kpak)
	digest.Write(id)
	digest.Write(pvt)
	return digest.Sum(nil)
}

// eccsiHE computes hash( HS || r || M ).
func eccsiHE(hs, r, message []byte) []byte {
	digest := sha256.New()
	digest.Write(hs)
	digest.Write(r)
	digest.Write(message)
	return digest.Sum(nil)
}

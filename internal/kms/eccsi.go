package kms

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// ECCSI key material, IETF RFC 6507 clause 5.1. RFC 6509 clause 2.1.1
// fixes the curve and hash for MIKEY-SAKKE: the P-256 curve and base
// point of FIPS 186-3 with SHA-256, so N = 32 octets.
//
// The KMS Public Authentication Key KPAK becomes the KMS certificate's
// PubAuthKey; the (SSK, PVT) pair becomes the key set's
// UserSigningKeySSK and UserPubTokenPVT.

const eccsiOctets = 32

// ECCSIKeyPair is a KMS signing master secret and its public root of
// trust.
type ECCSIKeyPair struct {
	// Secret is the KSAK, a random non-zero integer modulo q.
	Secret *big.Int
	// Public is KPAK = [KSAK]G.
	Public []byte
}

func eccsiCurve() elliptic.Curve { return elliptic.P256() }

// GenerateECCSIKeyPair chooses a KSAK at random and fixes KPAK = [KSAK]G
// (RFC 6507 clause 4.2).
func GenerateECCSIKeyPair() (*ECCSIKeyPair, error) {
	order := eccsiCurve().Params().N
	for {
		ksak, err := rand.Int(rand.Reader, order)
		if err != nil {
			return nil, fmt.Errorf("ECCSI KSAK: %w", err)
		}
		if ksak.Sign() == 0 {
			continue
		}
		return NewECCSIKeyPair(ksak)
	}
}

// NewECCSIKeyPair derives KPAK for an already-chosen KSAK.
func NewECCSIKeyPair(ksak *big.Int) (*ECCSIKeyPair, error) {
	order := eccsiCurve().Params().N
	if ksak == nil || ksak.Sign() <= 0 || ksak.Cmp(order) >= 0 {
		return nil, errors.New("ECCSI KSAK must be a non-zero integer modulo q")
	}
	x, y := eccsiCurve().ScalarBaseMult(ksak.Bytes())
	return &ECCSIKeyPair{
		Secret: new(big.Int).Set(ksak),
		Public: elliptic.Marshal(eccsiCurve(), x, y),
	}, nil
}

// SigningKey is the per-identity ECCSI key material handed to a client.
type SigningKey struct {
	// SSK is the Secret Signing Key, an integer, transported
	// confidentiality-protected.
	SSK []byte
	// PVT is the Public Validation Token, an elliptic curve point.
	PVT []byte
	// HS is hash( G || KPAK || ID || PVT ), which RFC 6507 clause 5.1.2
	// says a client should store alongside the SSK.
	HS []byte
}

// NewSigningKey constructs an (SSK, PVT) pair for an identifier per
// RFC 6507 clause 5.1.1, choosing the ephemeral v at random and
// restarting if the procedure produces a zero SSK or HS.
func (kp *ECCSIKeyPair) NewSigningKey(id []byte) (*SigningKey, error) {
	order := eccsiCurve().Params().N
	for attempt := 0; attempt < 8; attempt++ {
		v, err := rand.Int(rand.Reader, order)
		if err != nil {
			return nil, fmt.Errorf("ECCSI ephemeral: %w", err)
		}
		if v.Sign() == 0 {
			continue
		}
		key, err := kp.signingKeyWithEphemeral(id, v)
		if errors.Is(err, errDegenerateEphemeral) {
			continue
		}
		return key, err
	}
	return nil, errors.New("ECCSI key construction did not converge")
}

// errDegenerateEphemeral marks step 5 of RFC 6507 clause 5.1.1: the SSK
// or HS came out zero modulo q, so the KMS must restart with a fresh v.
var errDegenerateEphemeral = errors.New("degenerate ephemeral")

// signingKeyWithEphemeral is the deterministic core of clause 5.1.1,
// separated so the RFC's test vector, which fixes v, can be pinned.
func (kp *ECCSIKeyPair) signingKeyWithEphemeral(id []byte, v *big.Int) (*SigningKey, error) {
	curve := eccsiCurve()
	order := curve.Params().N

	// Step 2: PVT = [v]G in canonical uncompressed form.
	px, py := curve.ScalarBaseMult(v.Bytes())
	pvt := elliptic.Marshal(curve, px, py)

	// Step 3: HS = hash( G || KPAK || ID || PVT ).
	base := elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy)
	digest := sha256.New()
	digest.Write(base)
	digest.Write(kp.Public)
	digest.Write(id)
	digest.Write(pvt)
	hs := digest.Sum(nil)

	hsInt := new(big.Int).SetBytes(hs)
	if new(big.Int).Mod(hsInt, order).Sign() == 0 {
		return nil, errDegenerateEphemeral
	}

	// Step 4: SSK = ( KSAK + HS * v ) modulo q.
	ssk := new(big.Int).Mul(hsInt, v)
	ssk.Add(ssk, kp.Secret)
	ssk.Mod(ssk, order)
	if ssk.Sign() == 0 {
		return nil, errDegenerateEphemeral
	}

	out := make([]byte, eccsiOctets)
	ssk.FillBytes(out)
	return &SigningKey{SSK: out, PVT: pvt, HS: hs}, nil
}

// ValidateSigningKey runs the client-side check of RFC 6507 clause
// 5.1.2: PVT lies on the curve and KPAK = [SSK]G - [HS]PVT.
func (kp *ECCSIKeyPair) ValidateSigningKey(id []byte, key *SigningKey) error {
	curve := eccsiCurve()
	px, py := elliptic.Unmarshal(curve, key.PVT)
	if px == nil {
		return errors.New("PVT is not a valid point of the curve")
	}

	base := elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy)
	digest := sha256.New()
	digest.Write(base)
	digest.Write(kp.Public)
	digest.Write(id)
	digest.Write(key.PVT)
	hs := new(big.Int).SetBytes(digest.Sum(nil))

	sx, sy := curve.ScalarBaseMult(key.SSK)
	hx, hy := curve.ScalarMult(px, py, hs.Bytes())
	// Subtracting a point is adding its inverse, (x, -y).
	hy = new(big.Int).Sub(curve.Params().P, hy)
	rx, ry := curve.Add(sx, sy, hx, hy)

	if elliptic.Marshal(curve, rx, ry) == nil ||
		string(elliptic.Marshal(curve, rx, ry)) != string(kp.Public) {
		return errors.New("signing key does not verify against KPAK")
	}
	return nil
}

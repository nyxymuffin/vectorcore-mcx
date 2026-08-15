// Package kms implements the MCX Key Management Server of TS 33.180
// clause 5.3: the identity-based key material (ECCSI signing keys of
// IETF RFC 6507 and SAKKE decryption keys of IETF RFC 6508) that MC
// clients, MCX servers and group management servers are provisioned with,
// and the MIKEY-SAKKE UID derivation of TS 33.180 Annex F.2.1.
//
// Only the KMS half of the two schemes lives here. Key extraction needs
// nothing but elliptic curve scalar multiplication; the bilinear pairing
// of RFC 6508 clause 3.2 is required for SAKKE encryption and decryption,
// which are performed by the clients, not by the KMS.
package kms

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Parameter Set 1 of IETF RFC 6509 Appendix A, the parameter set that
// TS 33.180 clause 5.3.5 refers to through the KMS certificate's
// ParameterSet field. The curve is E(F_p): y^2 = x^3 - 3x over the
// 1024-bit prime p, P is a point of prime order q, and elements are
// 128-octet strings (L = Ceiling(lg(p)/8)).
//
// The hexadecimal is laid out in the RFC's own rows so it can be compared
// against the document line by line.
const (
	ParameterSet1 = 1

	// sakkeOctets is L, the length of the octet string representing an
	// element of F_p (RFC 6508 clause 4).
	sakkeOctets = 128

	primeHex = "997ABB1F0A563FDA65C61198DAD0657A" +
		"416C0CE19CB48261BE9AE358B3E01A2E" +
		"F40AAB27E2FC0F1B228730D531A59CB0" +
		"E791B39FF7C88A19356D27F4A666A6D0" +
		"E26C6487326B4CD4512AC5CD65681CE1" +
		"B6AFF4A831852A82A7CF3C521C3C09AA" +
		"9F94D6AF56971F1FFCE3E82389857DB0" +
		"80C5DF10AC7ACE87666D807AFEA85FEB"

	orderHex = "265EAEC7C2958FF69971846636B4195E" +
		"905B0338672D20986FA6B8D62CF8068B" +
		"BD02AAC9F8BF03C6C8A1CC354C69672C" +
		"39E46CE7FDF222864D5B49FD2999A9B4" +
		"389B1921CC9AD335144AB173595A0738" +
		"6DABFD2A0C614AA0A9F3CF14870F026A" +
		"A7E535ABD5A5C7C7FF38FA08E2615F6C" +
		"203177C42B1EB3A1D99B601EBFAA17FB"

	generatorXHex = "53FC09EE332C29AD0A7990053ED9B52A" +
		"2B1A2FD60AEC69C698B2F204B6FF7CBF" +
		"B5EDB6C0F6CE2308AB10DB9030B09E10" +
		"43D5F22CDB9DFA55718BD9E7406CE890" +
		"9760AF765DD5BCCB337C86548B72F2E1" +
		"A702C3397A60DE74A7C1514DBA66910D" +
		"D5CFB4CC80728D87EE9163A5B63F73EC" +
		"80EC46C4967E0979880DC8ABEAE63895"

	generatorYHex = "0A8249063F6009F1F9F1F0533634A135" +
		"D3E82016029906963D778D821E141178" +
		"F5EA69F4654EC2B9E7F7F5E5F0DE55F6" +
		"6B598CCF9A140B2E416CFF0CA9E032B9" +
		"70DAE117AD547C6CCAD696B5B7652FE0" +
		"AC6F1E80164AA989492D979FC5A4D5F2" +
		"13515AD7E9CB99A980BDAD5AD5BB4636" +
		"ADB9B5706A67DCDE75573FD71BEF16D7"
)

var (
	sakkeP = mustHexInt(primeHex)
	sakkeQ = mustHexInt(orderHex)
	// sakkeBase is P, the generator of the order-q subgroup.
	sakkeBase = &point{X: mustHexInt(generatorXHex), Y: mustHexInt(generatorYHex)}

	big3 = big.NewInt(3)
)

func mustHexInt(h string) *big.Int {
	v, ok := new(big.Int).SetString(strings.ReplaceAll(h, " ", ""), 16)
	if !ok {
		panic("kms: malformed parameter constant")
	}
	return v
}

// point is an affine point of E(F_p). The point at infinity is
// represented by nil coordinates, which is why callers construct it only
// through infinity().
type point struct {
	X, Y *big.Int
}

func infinity() *point { return &point{} }

func (pt *point) isInfinity() bool { return pt == nil || pt.X == nil || pt.Y == nil }

// onCurve reports whether the point satisfies y^2 = x^3 - 3x mod p. The
// point at infinity is on the curve by definition.
func (pt *point) onCurve() bool {
	if pt.isInfinity() {
		return true
	}
	if pt.X.Sign() < 0 || pt.X.Cmp(sakkeP) >= 0 || pt.Y.Sign() < 0 || pt.Y.Cmp(sakkeP) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(pt.Y, pt.Y)
	lhs.Mod(lhs, sakkeP)

	rhs := new(big.Int).Mul(pt.X, pt.X)
	rhs.Mul(rhs, pt.X)
	rhs.Sub(rhs, new(big.Int).Mul(big3, pt.X))
	rhs.Mod(rhs, sakkeP)

	return lhs.Cmp(rhs) == 0
}

func (pt *point) equal(other *point) bool {
	if pt.isInfinity() || other.isInfinity() {
		return pt.isInfinity() && other.isInfinity()
	}
	return pt.X.Cmp(other.X) == 0 && pt.Y.Cmp(other.Y) == 0
}

// double returns 2*pt using the chord-and-tangent formula for a = -3.
func (pt *point) double() *point {
	if pt.isInfinity() || pt.Y.Sign() == 0 {
		return infinity()
	}
	// lambda = (3x^2 - 3) / (2y)
	num := new(big.Int).Mul(pt.X, pt.X)
	num.Mul(num, big3)
	num.Sub(num, big3)
	den := new(big.Int).Lsh(pt.Y, 1)
	return pt.chord(pt, num, den)
}

// add returns pt+other.
func (pt *point) add(other *point) *point {
	switch {
	case pt.isInfinity():
		return other
	case other.isInfinity():
		return pt
	case pt.X.Cmp(other.X) == 0:
		// Either the same point (tangent) or mutual inverses (infinity).
		if pt.Y.Cmp(other.Y) == 0 {
			return pt.double()
		}
		return infinity()
	}
	num := new(big.Int).Sub(other.Y, pt.Y)
	den := new(big.Int).Sub(other.X, pt.X)
	return pt.chord(other, num, den)
}

// chord completes an addition or doubling once the slope has been
// expressed as num/den.
func (pt *point) chord(other *point, num, den *big.Int) *point {
	den.Mod(den, sakkeP)
	inv := new(big.Int).ModInverse(den, sakkeP)
	if inv == nil {
		return infinity()
	}
	lambda := num.Mod(num, sakkeP)
	lambda.Mul(lambda, inv)
	lambda.Mod(lambda, sakkeP)

	x := new(big.Int).Mul(lambda, lambda)
	x.Sub(x, pt.X)
	x.Sub(x, other.X)
	x.Mod(x, sakkeP)

	y := new(big.Int).Sub(pt.X, x)
	y.Mul(y, lambda)
	y.Sub(y, pt.Y)
	y.Mod(y, sakkeP)

	return &point{X: x, Y: y}
}

// scalarMult returns [k]pt.
//
// The scalar is blinded before the ladder runs: because pt has order q,
// adding a random multiple of q leaves the result unchanged while giving
// every multiplication the same iteration count regardless of how many
// leading zero bits the secret scalar has. The per-bit branch that
// remains is a dummy-add ladder, so the work per bit does not depend on
// the bit either.
func scalarMult(k *big.Int, pt *point) (*point, error) {
	k = new(big.Int).Mod(k, sakkeQ)
	if k.Sign() == 0 || pt.isInfinity() {
		return infinity(), nil
	}
	blind, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, fmt.Errorf("scalar blinding: %w", err)
	}
	blinded := new(big.Int).Add(k, new(big.Int).Mul(blind, sakkeQ))

	result := infinity()
	for i := sakkeQ.BitLen() + 64; i >= 0; i-- {
		result = result.double()
		sum := result.add(pt)
		if blinded.Bit(i) == 1 {
			result = sum
		}
	}
	if !result.onCurve() {
		return nil, errors.New("scalar multiplication left the curve")
	}
	return result, nil
}

// marshalPoint encodes a point in the uncompressed form required by
// RFC 6508 clause 4: 0x04 || x || y, each coordinate an L-octet string.
func marshalPoint(pt *point) ([]byte, error) {
	if pt.isInfinity() {
		return nil, errors.New("cannot encode the point at infinity")
	}
	out := make([]byte, 1+2*sakkeOctets)
	out[0] = 4
	pt.X.FillBytes(out[1 : 1+sakkeOctets])
	pt.Y.FillBytes(out[1+sakkeOctets:])
	return out, nil
}

// unmarshalPoint parses the uncompressed encoding and checks that the
// result is a point of the curve.
func unmarshalPoint(b []byte) (*point, error) {
	if len(b) != 1+2*sakkeOctets || b[0] != 4 {
		return nil, fmt.Errorf("expected a %d-octet uncompressed point", 1+2*sakkeOctets)
	}
	pt := &point{
		X: new(big.Int).SetBytes(b[1 : 1+sakkeOctets]),
		Y: new(big.Int).SetBytes(b[1+sakkeOctets:]),
	}
	if !pt.onCurve() {
		return nil, errors.New("point is not on the SAKKE curve")
	}
	return pt, nil
}

package kms

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

// The Tate-Lichtenbaum pairing of IETF RFC 6508 clause 3.2 and the
// arithmetic it rests on.
//
// The KMS does not need the pairing to issue key material, but an MCX
// Server does need it to consume MIKEY-SAKKE payloads addressed to its
// own identity, which is what the CSK upload of TS 33.180 clause 5.4
// requires.

// fp2 is an element of F_p^2 = F_p[i] with i^2 + 1 = 0, written a + i*b
// (RFC 6508 clause 2.1).
type fp2 struct {
	A, B *big.Int
}

func newFp2(a, b int64) fp2 {
	return fp2{A: big.NewInt(a), B: big.NewInt(b)}
}

func (x fp2) mul(y fp2) fp2 {
	// (a1 + i*b1)(a2 + i*b2) = (a1a2 - b1b2) + i(a1b2 + a2b1)
	ac := new(big.Int).Mul(x.A, y.A)
	bd := new(big.Int).Mul(x.B, y.B)
	real := new(big.Int).Sub(ac, bd)
	real.Mod(real, sakkeP)

	ad := new(big.Int).Mul(x.A, y.B)
	bc := new(big.Int).Mul(x.B, y.A)
	imag := new(big.Int).Add(ad, bc)
	imag.Mod(imag, sakkeP)

	return fp2{A: real, B: imag}
}

func (x fp2) square() fp2 { return x.mul(x) }

// exp raises an F_p^2 element to an integer power by square and multiply.
func (x fp2) exp(e *big.Int) fp2 {
	result := newFp2(1, 0)
	for i := e.BitLen() - 1; i >= 0; i-- {
		result = result.square()
		if e.Bit(i) == 1 {
			result = result.mul(x)
		}
	}
	return result
}

// projective reduces an element of F_p^2 to the F_p representative of the
// element of PF_p it stands for: for t = a + i*b the representative is
// b/a (RFC 6508 clause 3.2).
func (x fp2) projective() (*big.Int, error) {
	inv := new(big.Int).ModInverse(new(big.Int).Mod(x.A, sakkeP), sakkeP)
	if inv == nil {
		return nil, errors.New("pairing produced a value with no F_p representative")
	}
	out := new(big.Int).Mul(x.B, inv)
	return out.Mod(out, sakkeP), nil
}

// pfpMul multiplies two elements of PF_p[q] in their F_p representation:
// A * B is represented by (a + b)/(1 - a*b) (RFC 6508 clause 2.1).
func pfpMul(a, b *big.Int) (*big.Int, error) {
	num := new(big.Int).Add(a, b)
	den := new(big.Int).Mul(a, b)
	den.Sub(big.NewInt(1), den)
	den.Mod(den, sakkeP)

	inv := new(big.Int).ModInverse(den, sakkeP)
	if inv == nil {
		return nil, errors.New("PF_p multiplication has no inverse")
	}
	out := num.Mul(num, inv)
	return out.Mod(out, sakkeP), nil
}

// pfpExp raises an element of PF_p[q], in its F_p representation, to an
// integer power. RFC 6508 clause 6.2.1 step 4a is explicit that g^r must
// use the PF_p group operation and not ordinary F_p arithmetic.
func pfpExp(base, e *big.Int) (*big.Int, error) {
	// The identity of PF_p[q] in this representation is 0: it is the
	// coset of F_p*, whose representative b/a is 0/1.
	result := big.NewInt(0)
	acc := new(big.Int).Set(base)
	for i := 0; i < e.BitLen(); i++ {
		if e.Bit(i) == 1 {
			var err error
			if result, err = pfpMul(result, acc); err != nil {
				return nil, err
			}
		}
		var err error
		if acc, err = pfpMul(acc, acc); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// pair computes <R, Q> for points of E(F_p)[q], following the pseudocode
// of RFC 6508 clause 3.2, and returns the F_p representative of the
// result.
func pair(r, q *point) (*big.Int, error) {
	if r.isInfinity() || q.isInfinity() {
		return nil, errors.New("the pairing is not defined at infinity")
	}

	v := newFp2(1, 0)
	c := new(big.Int).Add(sakkeP, big.NewInt(1))
	c.Div(c, sakkeQ)
	cur := &point{X: new(big.Int).Set(r.X), Y: new(big.Int).Set(r.Y)}

	// The loop runs over the bits of q-1 from the second most
	// significant down to the least.
	exponent := new(big.Int).Sub(sakkeQ, big.NewInt(1))
	for i := exponent.BitLen() - 2; i >= 0; i-- {
		// l is the gradient of the line through C, C and [-2]C.
		num := new(big.Int).Mul(cur.X, cur.X)
		num.Sub(num, big.NewInt(1))
		num.Mul(num, big3)
		den := new(big.Int).Lsh(cur.Y, 1)
		l, err := divMod(num, den)
		if err != nil {
			return nil, err
		}

		v = v.square().mul(lineAt(l, q, cur))
		cur = cur.double()

		if exponent.Bit(i) == 1 {
			// l is the gradient of the line through C, R and -C-R.
			num := new(big.Int).Sub(cur.Y, r.Y)
			den := new(big.Int).Sub(cur.X, r.X)
			l, err := divMod(num, den)
			if err != nil {
				return nil, err
			}
			v = v.mul(lineAt(l, q, cur))
			cur = cur.add(r)
		}
	}
	return v.exp(c).projective()
}

// lineAt evaluates the line of gradient l at the image of Q under the
// distortion map: l*( Q_x + C_x ) + ( i*Q_y - C_y ).
func lineAt(l *big.Int, q, cur *point) fp2 {
	real := new(big.Int).Add(q.X, cur.X)
	real.Mul(real, l)
	real.Sub(real, cur.Y)
	real.Mod(real, sakkeP)
	return fp2{A: real, B: new(big.Int).Mod(q.Y, sakkeP)}
}

func divMod(num, den *big.Int) (*big.Int, error) {
	inv := new(big.Int).ModInverse(new(big.Int).Mod(den, sakkeP), sakkeP)
	if inv == nil {
		return nil, errors.New("division by a non-invertible element of F_p")
	}
	out := new(big.Int).Mod(num, sakkeP)
	out.Mul(out, inv)
	return out.Mod(out, sakkeP), nil
}

// hashToIntegerRange is the function of RFC 6508 clause 5.1: it hashes a
// string into the range 0 to n-1.
func hashToIntegerRange(s []byte, n *big.Int) *big.Int {
	const hashOctets = sha256.Size

	a := sha256.Sum256(s)
	h := make([]byte, hashOctets) // h_0 is a string of null bits

	// l = Ceiling( lg(n) / hashlen ), the number of hash blocks needed to
	// cover the range.
	blocks := (n.BitLen() + hashOctets*8 - 1) / (hashOctets * 8)
	if blocks < 1 {
		blocks = 1
	}

	var v []byte
	for i := 0; i < blocks; i++ {
		next := sha256.Sum256(h)
		h = next[:]
		block := sha256.Sum256(append(append([]byte{}, h...), a[:]...))
		v = append(v, block[:]...)
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(v), n)
}

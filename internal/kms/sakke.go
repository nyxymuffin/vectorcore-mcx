package kms

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// SAKKE key material, IETF RFC 6508 clause 6.1 as profiled by TS 33.180
// clauses 5.3.5 and 5.3.6.
//
// The KMS master secret z_T never leaves this package in encoded form;
// the public key Z_T becomes the KMS certificate's PubEncKey and each
// user's Receiver Secret Key becomes the key set's UserDecryptKey.

// SAKKEKeyPair is a KMS SAKKE master secret and its public key.
type SAKKEKeyPair struct {
	// Master is z_T, the KMS Master Secret.
	Master *big.Int
	// Public is Z_T = [z_T]P, published in the KMS certificate.
	Public *point
}

// GenerateSAKKEKeyPair chooses a KMS Master Secret at random in the range
// 2 to q-1 and derives the KMS Public Key (RFC 6508 clause 6.1).
func GenerateSAKKEKeyPair() (*SAKKEKeyPair, error) {
	for {
		z, err := rand.Int(rand.Reader, sakkeQ)
		if err != nil {
			return nil, fmt.Errorf("SAKKE master secret: %w", err)
		}
		if z.Cmp(big.NewInt(2)) < 0 {
			continue
		}
		return NewSAKKEKeyPair(z)
	}
}

// NewSAKKEKeyPair derives the public key for an already-chosen master
// secret, which is how a KMS reloads provisioned domain key material.
func NewSAKKEKeyPair(z *big.Int) (*SAKKEKeyPair, error) {
	if z == nil || z.Cmp(big.NewInt(2)) < 0 || z.Cmp(sakkeQ) >= 0 {
		return nil, errors.New("SAKKE master secret must be in the range 2 to q-1")
	}
	pub, err := scalarMult(z, sakkeBase)
	if err != nil {
		return nil, err
	}
	return &SAKKEKeyPair{Master: new(big.Int).Set(z), Public: pub}, nil
}

// PublicKey returns Z_T in the uncompressed encoding used by the KMS
// certificate's PubEncKey field.
func (kp *SAKKEKeyPair) PublicKey() ([]byte, error) {
	return marshalPoint(kp.Public)
}

// ReceiverSecretKey derives the RSK for an identifier, RFC 6508 clause
// 6.1.1: K_(a,T) = [(a + z_T)^-1]P, with the identifier interpreted as an
// integer and the inversion performed modulo q.
//
// uid is the 256-bit MIKEY-SAKKE UID of TS 33.180 Annex F.2.1, which is
// the 'a' of the RFC for MC service identities.
func (kp *SAKKEKeyPair) ReceiverSecretKey(uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		return nil, errors.New("identifier is empty")
	}
	a := new(big.Int).SetBytes(uid)
	sum := new(big.Int).Add(a, kp.Master)
	sum.Mod(sum, sakkeQ)
	if sum.Sign() == 0 {
		// a == -z_T mod q has no inverse. The odds are negligible, but
		// silently emitting a bad key would be worse than refusing.
		return nil, errors.New("identifier is not invertible under this master secret")
	}
	inv := new(big.Int).ModInverse(sum, sakkeQ)
	if inv == nil {
		return nil, errors.New("identifier is not invertible under this master secret")
	}
	rsk, err := scalarMult(inv, sakkeBase)
	if err != nil {
		return nil, err
	}
	return marshalPoint(rsk)
}

// ValidateReceiverSecretKey performs the check a provisioned client would
// perform, in the form available without a pairing: RSK is a point of the
// curve and [a + z_T]RSK is the generator P. Recovering P proves the RSK
// was derived from this master secret for this identifier.
func (kp *SAKKEKeyPair) ValidateReceiverSecretKey(uid, rsk []byte) error {
	pt, err := unmarshalPoint(rsk)
	if err != nil {
		return err
	}
	a := new(big.Int).SetBytes(uid)
	sum := new(big.Int).Add(a, kp.Master)
	sum.Mod(sum, sakkeQ)
	recovered, err := scalarMult(sum, pt)
	if err != nil {
		return err
	}
	if !recovered.equal(sakkeBase) {
		return errors.New("receiver secret key does not verify against the master secret")
	}
	return nil
}

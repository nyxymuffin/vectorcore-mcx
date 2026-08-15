package kms

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"time"
)

// MIKEY-SAKKE UID generation, TS 33.180 Annex F.2.1.
//
// RFC 6509 clause 3.2 only defines an identifier format for Tel-URIs with
// monthly key periods, which MC service IDs do not fit, so TS 33.180
// defines its own: the UID is the SHA-256 of a fixed string, the user
// identifier, the KMS identifier and the key period parameters, each
// followed by its length, encoded as in clause B.2 of TS 33.220.

// uidFixedString is P0, the fixed 15 character string.
const uidFixedString = "MIKEY-SAKKE-UID"

// ntpEpochOffset converts Unix time to the NTP timescale used throughout
// Annex F.2.1: seconds since 0h on 1 January 1900.
const ntpEpochOffset = 2208988800

// KeyPeriod describes the segmentation of time into key periods, taken
// from the KMS certificate's UserKeyPeriod and UserKeyOffset fields
// (TS 33.180 table D.3.2.2-1).
type KeyPeriod struct {
	// LengthSeconds is P3, the number of seconds in every key period
	// (e.g. 2592000 for four weeks).
	LengthSeconds int64
	// OffsetSeconds is P4, the offset of the first key period from 0h on
	// 1 January 1900, which shall be less than the period length.
	OffsetSeconds int64
}

// Validate rejects a segmentation that Annex F.2.1 does not allow.
func (kp KeyPeriod) Validate() error {
	if kp.LengthSeconds <= 0 {
		return errors.New("key period length must be positive")
	}
	if kp.OffsetSeconds < 0 || kp.OffsetSeconds >= kp.LengthSeconds {
		return errors.New("key period offset must be less than the period length")
	}
	return nil
}

// Number returns P5, the current key period number since 0h on
// 1 January 1900: Floor( ( TIME - P4 ) / P3 ).
func (kp KeyPeriod) Number(at time.Time) int64 {
	ntp := at.Unix() + ntpEpochOffset
	return (ntp - kp.OffsetSeconds) / kp.LengthSeconds
}

// Bounds returns the wall-clock instants at which the given key period
// starts and ends, which become the ValidFrom and ValidTo of a key set.
func (kp KeyPeriod) Bounds(number int64) (time.Time, time.Time) {
	start := kp.OffsetSeconds + number*kp.LengthSeconds - ntpEpochOffset
	return time.Unix(start, 0).UTC(), time.Unix(start+kp.LengthSeconds, 0).UTC()
}

// UID derives the 256-bit MIKEY-SAKKE UID for an MC service identity
// under a KMS for one key period. The result is the raw hash; TS 33.180
// says the UID "shall be base64 encoded" when carried in the KmsKeySet
// UserID field, which the XML encoder does.
func UID(identity, kmsURI string, period KeyPeriod, number int64) ([]byte, error) {
	if identity == "" {
		return nil, errors.New("identity is empty")
	}
	if kmsURI == "" {
		return nil, errors.New("KMS URI is empty")
	}
	if err := period.Validate(); err != nil {
		return nil, err
	}

	digest := sha256.New()
	// FC = 0x00. Annex F.2.1 note 1: the TS 33.220 key derivation
	// function is not used, so this is a dummy value.
	digest.Write([]byte{0x00})
	writeUIDParam(digest, []byte(uidFixedString))
	writeUIDParam(digest, []byte(identity))
	writeUIDParam(digest, []byte(kmsURI))
	writeUIDParam(digest, uidInteger(period.LengthSeconds))
	writeUIDParam(digest, uidInteger(period.OffsetSeconds))
	writeUIDParam(digest, uidInteger(number))
	return digest.Sum(nil), nil
}

// UIDAt derives the UID for the key period containing the given instant.
func UIDAt(identity, kmsURI string, period KeyPeriod, at time.Time) ([]byte, int64, error) {
	if err := period.Validate(); err != nil {
		return nil, 0, err
	}
	number := period.Number(at)
	uid, err := UID(identity, kmsURI, period, number)
	return uid, number, err
}

// writeUIDParam appends Pn followed by Ln, its length as a two-octet
// big-endian integer, per clause B.2 of TS 33.220.
func writeUIDParam(w interface{ Write([]byte) (int, error) }, value []byte) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	w.Write(value)
	w.Write(length[:])
}

// uidInteger encodes an integer parameter as the shortest big-endian
// octet string that represents it; zero is a single zero octet.
func uidInteger(v int64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	return new(big.Int).SetInt64(v).Bytes()
}

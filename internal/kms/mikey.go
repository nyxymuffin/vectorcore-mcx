package kms

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// MIKEY-SAKKE I_MESSAGEs, IETF RFC 6509 clause 2.2 as profiled by
// TS 33.180 Annex E.
//
// One of these carries every key TS 33.180 distributes over SIP: the GMK
// a group management server sends a client (clause 5.7 and Annex E.2),
// the PCK of a private call (clause 5.6, Annex E.3) and the CSK a client
// uploads to the MCX Server (clause 5.4, Annex E.4). The key itself
// travels inside the SAKKE payload as the Shared Secret Value; the rest
// of the message says who it is from, who it is for, whose KMS vouches
// for each of them, and carries the signature over the whole thing.

// MIKEY payload type identifiers (RFC 3830 table 6.1.b, extended by
// RFC 6509 table 2).
const (
	payloadLast   = 0
	payloadSIGN   = 4
	payloadT      = 5
	payloadSP     = 10
	payloadRAND   = 11
	payloadIDR    = 14
	payloadSAKKE  = 26
	dataTypeSAKKE = 26
)

// ID roles of RFC 6043 table 6.11, extended by RFC 6509 table 7.
const (
	roleInitiator = 1
	roleResponder = 2
	roleKMSi      = 6
	roleKMSr      = 7
)

// idTypeURI is the ID Type of RFC 3830 table 6.7.a. MC service
// identities and KMS identities are both URIs.
const idTypeURI = 1

const (
	// mikeyVersion is 0x01, MIKEY as defined in RFC 3830.
	mikeyVersion = 1
	// sigTypeECCSI is S type '2' (RFC 6509 table 6), which TS 33.180
	// clause E.1.2 requires.
	sigTypeECCSI = 2
	// idSchemeMCXHashedUID is ID scheme '2', the value TS 33.180
	// clause E.1.2 assigns to the UID generation of clause F.2.1.
	idSchemeMCXHashedUID = 2
	// tsTypeNTPUTC is TS type 0, which clause E.1.2 requires.
	tsTypeNTPUTC = 0
	// randLength is the RAND size; RFC 3830 clause 6.11 wants at least 16.
	randLength = 16
)

// IMessage is a MIKEY-SAKKE I_MESSAGE in the form TS 33.180 Annex E
// requires: the mandatory payloads of clause E.1.2, in the order they
// appear on the wire.
type IMessage struct {
	// CSBID is the Crypto Session Bundle ID. Clause E.2.1 makes it the
	// GUK-ID for a GMK; other uses carry the relevant key identifier.
	CSBID uint32
	// Timestamp is the NTP-UTC time of the TS payload.
	Timestamp time.Time
	// RAND is the randomness session keys are derived from.
	RAND []byte

	// InitiatorURI and ResponderURI are the IDRi and IDRr payloads: the
	// sender's and recipient's MC service identities.
	InitiatorURI string
	ResponderURI string
	// InitiatorKMSURI and ResponderKMSURI are IDRkmsi and IDRkmsr, the
	// roots of trust for the signature and for the key exchange.
	InitiatorKMSURI string
	ResponderKMSURI string

	// SAKKE is the encapsulated key.
	SAKKE *Encapsulation

	// Signature is the ECCSI signature over the whole message. It is
	// filled in by Sign and checked by Verify.
	Signature []byte
}

// ntpEpochSeconds converts an instant to the NTP timescale the TS
// payload uses.
func ntpTimestamp(t time.Time) uint64 {
	seconds := uint64(t.Unix() + ntpEpochOffset)
	// The low 32 bits are the fraction of a second.
	fraction := uint64(t.Nanosecond()) << 32 / 1e9
	return seconds<<32 | fraction
}

func ntpTime(v uint64) time.Time {
	seconds := int64(v>>32) - ntpEpochOffset
	nanos := int64((v & 0xffffffff) * 1e9 >> 32)
	return time.Unix(seconds, nanos).UTC()
}

// NewIMessage builds an unsigned I_MESSAGE encapsulating ssv to the
// responder's UID under the responder's KMS public key.
func NewIMessage(csbID uint32, ssv, responderUID, responderKMSPublic []byte) (*IMessage, error) {
	enc, err := Encapsulate(ssv, responderUID, responderKMSPublic)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, randLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("MIKEY RAND: %w", err)
	}
	return &IMessage{
		CSBID:     csbID,
		Timestamp: time.Now().UTC(),
		RAND:      nonce,
		SAKKE:     enc,
	}, nil
}

// Marshal encodes the message. The signature payload is always present,
// because clause E.1.2 requires it; Sign fills it with a real signature
// and this method emits whatever Signature currently holds, which is how
// the bytes to be signed are produced.
func (m *IMessage) Marshal() ([]byte, error) {
	if m.SAKKE == nil {
		return nil, errors.New("a MIKEY-SAKKE message needs a SAKKE payload")
	}
	if len(m.RAND) == 0 {
		return nil, errors.New("a MIKEY-SAKKE message needs a RAND payload")
	}

	// The payloads follow the header in the order clause E.1.2 lists
	// them, each naming the one after it.
	out := make([]byte, 0, 1024)

	// Common Header (RFC 3830 clause 6.1). CS# is 0 and the CS ID map
	// type is 1 (empty map), which clause E.1.2 says selects the default
	// security profiles.
	out = append(out, mikeyVersion, dataTypeSAKKE, payloadT)
	out = append(out, 0x01) // V = 0, PRF func = 1 (PRF-HMAC-SHA-256)
	out = binary.BigEndian.AppendUint32(out, m.CSBID)
	out = append(out, 0x00, 0x01) // #CS = 0, CS ID map type = 1 (empty)

	// Timestamp (RFC 3830 clause 6.6).
	out = append(out, payloadRAND, tsTypeNTPUTC)
	out = binary.BigEndian.AppendUint64(out, ntpTimestamp(m.Timestamp))

	// RAND (RFC 3830 clause 6.11).
	out = append(out, payloadIDR, byte(len(m.RAND)))
	out = append(out, m.RAND...)

	// The four IDR payloads (RFC 6043 clause 6.6, RFC 6509 clause 4.4).
	idrs := []struct {
		role byte
		uri  string
	}{
		{roleInitiator, m.InitiatorURI},
		{roleResponder, m.ResponderURI},
		{roleKMSi, m.InitiatorKMSURI},
		{roleKMSr, m.ResponderKMSURI},
	}
	for i, idr := range idrs {
		next := byte(payloadIDR)
		if i == len(idrs)-1 {
			next = payloadSAKKE
		}
		if idr.uri == "" {
			return nil, fmt.Errorf("IDR payload with role %d is empty", idr.role)
		}
		out = append(out, next, idr.role, idTypeURI)
		out = binary.BigEndian.AppendUint16(out, uint16(len(idr.uri)))
		out = append(out, idr.uri...)
	}

	// SAKKE (RFC 6509 clause 4.2).
	data := append(append([]byte{}, m.SAKKE.R...), m.SAKKE.H...)
	out = append(out, payloadSIGN, ParameterSet1, idSchemeMCXHashedUID)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	out = append(out, data...)

	// SIGN (RFC 3830 clause 6.5, S type from RFC 6509 clause 4.3). The
	// S type and length are inside the signed region: clause E.1.2 says
	// the signature covers the entire message including them.
	//
	// NOTE on the length: TS 33.180 clause E.1.2 states that the
	// Signature length field "shall be 32". An ECCSI signature is
	// r || s || PVT, which RFC 6507 clause 3.3 fixes at 4N+1 = 129
	// octets for the P-256 profile that clause E.1.2 itself selects with
	// S type 2; r and s alone are already 64. A 32-octet field cannot
	// carry the signature the same sentence calls for, so the length
	// written here is the 129 of the referenced RFC. See
	// docs/MCX-REMAINING-GAPS-2026-08-15.md.
	signature := m.Signature
	if signature == nil {
		signature = make([]byte, signatureLength)
	}
	header := uint16(sigTypeECCSI)<<12 | uint16(len(signature))
	out = binary.BigEndian.AppendUint16(out, header)
	return append(out, signature...), nil
}

// Sign computes the ECCSI signature over the entire message and stores
// it. Clause E.1.2: the signature is calculated over the whole MIKEY
// message including the S type and Signature length fields, then
// concatenated to the end.
func (m *IMessage) Sign(signer *Signer) error {
	m.Signature = nil
	body, err := m.Marshal()
	if err != nil {
		return err
	}
	// Everything but the placeholder signature is what gets signed.
	signature, err := signer.Sign(body[:len(body)-signatureLength])
	if err != nil {
		return err
	}
	m.Signature = signature
	return nil
}

// Unmarshal parses a MIKEY-SAKKE I_MESSAGE.
func Unmarshal(b []byte) (*IMessage, error) {
	r := &reader{buf: b}
	if r.u8() != mikeyVersion {
		return nil, errors.New("not a MIKEY version 1 message")
	}
	if r.u8() != dataTypeSAKKE {
		return nil, errors.New("not a MIKEY-SAKKE message")
	}
	next := r.u8()
	r.u8() // V and PRF func

	m := &IMessage{CSBID: r.u32()}
	if csCount := r.u8(); csCount != 0 {
		// Clause E.1.2 allows CS# > 0 with a GENERIC-ID map; this parser
		// handles only the empty map that the default security profiles
		// of Annexes E.2.2, E.3.2 and E.4.2 use.
		return nil, fmt.Errorf("crypto session maps are not supported (CS# = %d)", csCount)
	}
	r.u8() // CS ID map type

	for next != payloadLast && next != payloadSIGN && r.err == nil {
		switch next {
		case payloadT:
			next = r.u8()
			if r.u8() != tsTypeNTPUTC {
				return nil, errors.New("the timestamp is not NTP-UTC")
			}
			m.Timestamp = ntpTime(r.u64())
		case payloadRAND:
			next = r.u8()
			m.RAND = r.bytes(int(r.u8()))
		case payloadIDR:
			next = r.u8()
			role := r.u8()
			r.u8() // ID Type
			uri := string(r.bytes(int(r.u16())))
			switch role {
			case roleInitiator:
				m.InitiatorURI = uri
			case roleResponder:
				m.ResponderURI = uri
			case roleKMSi:
				m.InitiatorKMSURI = uri
			case roleKMSr:
				m.ResponderKMSURI = uri
			}
		case payloadSAKKE:
			next = r.u8()
			r.u8() // SAKKE params
			r.u8() // ID scheme
			data := r.bytes(int(r.u16()))
			if len(data) < 1+2*sakkeOctets+ssvBits/8 {
				return nil, errors.New("the SAKKE payload is too short")
			}
			split := 1 + 2*sakkeOctets
			m.SAKKE = &Encapsulation{R: data[:split], H: data[split:]}
		case payloadSP:
			// RFC 3830 clause 6.10. The policy is read past rather than
			// interpreted: this build applies the default profiles of
			// Annexes E.2.2, E.3.2 and E.4.2.
			next = r.u8()
			r.u8() // Policy no
			r.u8() // Prot type
			r.bytes(int(r.u16()))
		default:
			return nil, fmt.Errorf("unexpected MIKEY payload %d", next)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if next != payloadSIGN {
		return nil, errors.New("the message carries no SIGN payload")
	}

	header := r.u16()
	if header>>12 != sigTypeECCSI {
		return nil, fmt.Errorf("signature type %d is not ECCSI", header>>12)
	}
	m.Signature = r.bytes(int(header & 0x0fff))
	if r.err != nil {
		return nil, r.err
	}
	if m.SAKKE == nil {
		return nil, errors.New("the message carries no SAKKE payload")
	}
	return m, nil
}

// Verify checks the ECCSI signature over a received message against the
// signer's UID and the KPAK of the KMS named in its IDRkmsi payload.
// Clause E.1.2: the signature covers the entire message up to and
// including the S type and length fields.
func Verify(raw []byte, kpak, signerUID []byte) error {
	if len(raw) <= signatureLength {
		return errors.New("the message is too short to carry a signature")
	}
	return VerifySignature(kpak, signerUID,
		raw[:len(raw)-signatureLength], raw[len(raw)-signatureLength:])
}

// reader is a bounds-checked cursor over a MIKEY message.
type reader struct {
	buf []byte
	pos int
	err error
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if r.pos+n > len(r.buf) {
		r.err = errors.New("the MIKEY message is truncated")
		return false
	}
	return true
}

func (r *reader) u8() byte {
	if !r.need(1) {
		return 0
	}
	v := r.buf[r.pos]
	r.pos++
	return v
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v
}

func (r *reader) u64() uint64 {
	if !r.need(8) {
		return 0
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v
}

func (r *reader) bytes(n int) []byte {
	if n < 0 || !r.need(n) {
		return nil
	}
	v := r.buf[r.pos : r.pos+n]
	r.pos += n
	return v
}

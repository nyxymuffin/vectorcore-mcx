package sip

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/kms"
)

// CSK upload, TS 33.180 clauses 5.4 and 9.2.1.3.
//
// A client generates a 128-bit Client-Server Key, encapsulates it to the
// MCX Server's identity with the common key distribution mechanism of
// clause 5.2.2, and attaches the resulting MIKEY-SAKKE I_MESSAGE to its
// initial SIP REGISTER or to the PUBLISH that carries service
// authorisation, as an "application/mikey" body part. The server
// recovers the key and binds it to the user, giving the two a shared
// security context for the application-layer protection of clause 9.3.

// cskPurposeTag is the purpose tag of TS 33.180 Annex G table G-1: the
// four most significant bits of the key identifier are '2' for a CSK.
// The tag is what tells the receiving entity what kind of key arrived,
// so a payload carrying anything else is not a CSK upload.
const cskPurposeTag = 2

// clientServerKey is a CSK bound to the user that uploaded it.
type clientServerKey struct {
	Key      []byte
	KeyID    uint32
	Identity string
	// Received is when the upload was accepted. Clause 9.2.1.2: the key
	// stays in use until it is replaced, the session ends or the user
	// logs off, so it is held in memory rather than persisted.
	Received time.Time
}

// keyManagement is the MCX Server's own KMS-provisioned material,
// everything it needs to be the receiving entity of clause 5.2.2.
type keyManagement struct {
	// identity is the server's URI, whose UID keys are addressed to.
	identity string
	// uid is the MIKEY-SAKKE UID of that identity for the current key
	// period.
	uid []byte
	// rsk is the SAKKE Receiver Secret Key that decapsulates keys sent
	// to that UID.
	rsk []byte
	// kmsPublic is Z_T, needed for the clause 6.2.2 step 5 check.
	kmsPublic []byte
	// kpak is the root of trust that signatures are verified against.
	kpak []byte
	// domain derives the UID of a sending client from its URI.
	domain *kms.Domain
}

// cskStore holds the uploaded keys.
type cskStore struct {
	mu   sync.RWMutex
	keys map[string]*clientServerKey // MC service ID → key
}

func newCSKStore() *cskStore {
	return &cskStore{keys: map[string]*clientServerKey{}}
}

func (c *cskStore) put(k *clientServerKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys[strings.ToLower(k.Identity)] = k
}

// Get returns the CSK shared with an identity, if one has been uploaded.
func (c *cskStore) Get(identity string) (*clientServerKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	k, ok := c.keys[strings.ToLower(identity)]
	return k, ok
}

// forget drops the key for an identity, which is what clause 9.2.1.2
// calls for when the user logs off.
func (c *cskStore) forget(identity string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.keys, strings.ToLower(identity))
}

// initKeyManagement provisions the server's own key material from the
// co-located KMS. A deployment whose KMS lives elsewhere would fetch the
// same values over the Annex D interface instead; either way the server
// needs an RSK for its own identity before it can receive a CSK.
func (s *Server) initKeyManagement() {
	if !s.cfg.KMS.Enabled {
		return
	}
	// TS 24.379 clause 4.8: the CSK is protected to the public service
	// identity of the participating function serving the user, which a
	// deployment may expose under a different URI from the server's own
	// SIP identity.
	identity := strings.TrimSpace(s.cfg.KMS.ServerKeyIdentity)
	if identity == "" {
		identity = strings.TrimSpace(s.cfg.MCX.SIPIdentity)
	}
	if identity == "" {
		slog.Warn("CSK upload disabled: the MCX server has no identity to be addressed by")
		return
	}

	domain, err := kms.LoadDomain(s.cfg.KMS.KeyMaterialFile, kms.Domain{
		KMSURI:  s.cfg.KMS.KMSURI,
		CertURI: s.cfg.KMS.CertURI,
		Issuer:  s.cfg.KMS.Issuer,
		Period: kms.KeyPeriod{
			LengthSeconds: s.cfg.KMS.KeyPeriodSeconds,
			OffsetSeconds: s.cfg.KMS.KeyPeriodOffsetSeconds,
		},
	})
	if err != nil {
		slog.Error("CSK upload disabled: KMS domain unavailable", "err", err)
		return
	}

	km, err := serverKeyMaterial(domain, identity, time.Now().UTC())
	if err != nil {
		slog.Error("CSK upload disabled: server key material unavailable", "err", err)
		return
	}
	s.keyMgmt = km
	slog.Info("MCX server key material provisioned", "identity", identity, "kms_uri", domain.KMSURI)
}

// serverKeyMaterial derives the material for one identity and key
// period. It is separate from initKeyManagement so tests can provision a
// server without a configuration file.
func serverKeyMaterial(domain *kms.Domain, identity string, at time.Time) (*keyManagement, error) {
	set, err := domain.KeySet(identity, at)
	if err != nil {
		return nil, err
	}
	uid, err := kms.DecodeUserID(set.UserID)
	if err != nil {
		return nil, err
	}
	rsk, err := kms.DecodeKeyContent(set.DecryptKey)
	if err != nil {
		return nil, err
	}
	cert, err := domain.Certificate()
	if err != nil {
		return nil, err
	}
	enc, err := kms.DecodeHex(cert.PubEncKey)
	if err != nil {
		return nil, err
	}
	auth, err := kms.DecodeHex(cert.PubAuthKey)
	if err != nil {
		return nil, err
	}
	return &keyManagement{
		identity:  identity,
		uid:       uid,
		rsk:       rsk,
		kmsPublic: enc,
		kpak:      auth,
		domain:    domain,
	}, nil
}

// handleCSKUpload extracts a CSK from any "application/mikey" body part
// of a request. It reports whether a key was accepted; a request with no
// such part is not an upload and is not an error.
func (s *Server) handleCSKUpload(msg *Message, identity string) bool {
	part := msg.Part("application/mikey")
	if part == nil || len(part.Body) == 0 {
		return false
	}
	if s.keyMgmt == nil {
		slog.Warn("CSK upload ignored: this server holds no key material",
			"identity", identity)
		return false
	}
	if strings.TrimSpace(identity) == "" {
		slog.Warn("CSK upload ignored: the request carries no MC service identity")
		return false
	}

	key, err := s.extractCSK(part.Body, identity)
	if err != nil {
		slog.Warn("CSK upload rejected", "identity", identity, "err", err)
		return false
	}
	s.cskKeys.put(key)
	slog.Info("CSK upload accepted", "identity", identity, "csk_id", key.KeyID)
	return true
}

// extractCSK performs the key extraction of clause 5.2.2: verify the
// signature using the UID derived from the initiator's URI, then
// decapsulate the key with the server's own RSK.
func (s *Server) extractCSK(body []byte, identity string) (*clientServerKey, error) {
	km := s.keyMgmt
	message, err := kms.Unmarshal(body)
	if err != nil {
		return nil, err
	}

	// The initiator field names the sender. It must be the party the SIP
	// request came from: accepting a key signed by somebody else would
	// bind that third party's key to this user.
	sender := strings.TrimSpace(message.InitiatorURI)
	if sender == "" {
		sender = identity
	}
	if !strings.EqualFold(sender, identity) {
		return nil, errIdentityMismatch{sender: sender, identity: identity}
	}
	// The responder field must name this server, since the key is
	// encapsulated to its UID.
	if to := strings.TrimSpace(message.ResponderURI); to != "" &&
		!strings.EqualFold(to, km.identity) {
		return nil, errWrongResponder{to}
	}

	senderUID, _, err := kms.UIDAt(sender, km.domain.KMSURI, km.domain.Period, message.Timestamp)
	if err != nil {
		return nil, err
	}
	if err := kms.Verify(body, km.kpak, senderUID); err != nil {
		return nil, err
	}

	csk, err := kms.Decapsulate(message.SAKKE, km.uid, km.rsk, km.kmsPublic)
	if err != nil {
		return nil, err
	}
	// Clause 5.2.2: the key identifier lives in the CSB-ID field, and its
	// four most significant bits say what the key is for.
	if tag := message.CSBID >> 28; tag != cskPurposeTag {
		return nil, errWrongPurpose{tag}
	}
	return &clientServerKey{
		Key:      csk,
		KeyID:    message.CSBID,
		Identity: identity,
		Received: time.Now().UTC(),
	}, nil
}

type errIdentityMismatch struct{ sender, identity string }

func (e errIdentityMismatch) Error() string {
	return "the MIKEY initiator " + e.sender + " is not the sender of the SIP request " + e.identity
}

type errWrongResponder struct{ to string }

func (e errWrongResponder) Error() string {
	return "the key is addressed to " + e.to + ", not to this server"
}

type errWrongPurpose struct{ tag uint32 }

func (e errWrongPurpose) Error() string {
	return "the key identifier does not carry the CSK purpose tag"
}

// acceptCSKUpload looks for a CSK upload in a request and, in the
// application server posture, in the client's own request carried inside
// it (TS 24.379 clause 7.3.2 puts the client's REGISTER in a message/sip
// body part, and clause 9.2.1.3 of TS 33.180 puts the MIKEY payload
// beside it).
func (s *Server) acceptCSKUpload(msg *Message, identity string) {
	if s.keyMgmt == nil {
		return
	}
	s.handleCSKUpload(msg, identity)

	part := msg.Part("message/sip")
	if part == nil {
		return
	}
	inner, err := Parse(part.Body)
	if err != nil {
		return
	}
	innerIdentity := mcpttIdentityFromBody(inner)
	if innerIdentity == "" {
		innerIdentity = identity
	}
	s.handleCSKUpload(inner, innerIdentity)
}

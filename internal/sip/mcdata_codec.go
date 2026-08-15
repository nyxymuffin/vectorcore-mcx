package sip

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// MCData binary signalling messages, TS 24.282 clause 15: the
// application/vnd.3gpp.mcdata-signalling body is a compact binary message
// whose leading octet is the message type (clause 15.2.2, bits 1-6; bits 7-8
// are spare) followed by fixed-length mandatory IEs and optional TV IEs.
//
// Only what the server needs is decoded: the Conversation ID and Message ID
// that correlate a disposition notification to its original SDS
// (clause 12.2.3 steps 4-5), plus the disposition notification type for
// logging. Payload contents stay opaque and are relayed verbatim.

// Message types, table 15.2.2-1.
const (
	mcdataSDSSignallingPayload = 0x01
	mcdataFDSignallingPayload  = 0x02
	mcdataDataPayload          = 0x03
	mcdataSDSNotification      = 0x05
	mcdataFDNotification       = 0x06
)

// SDS disposition notification types, table 15.2.5-1.
const (
	mcdataDispositionDelivered      = 0x02
	mcdataDispositionRead           = 0x03
	mcdataDispositionDeliveredRead  = 0x04
	mcdataDispositionNotDeliverable = 0x01
)

// mcdataSignalling is the decoded head of an MCData signalling message.
type mcdataSignalling struct {
	MessageType      byte
	ConversationID   string // 16 octets, hex
	MessageID        string // 16 octets, hex
	NotificationType byte   // notifications only
}

// correlationKey identifies one SDS transmission.
func (m mcdataSignalling) correlationKey() string {
	return m.ConversationID + "/" + m.MessageID
}

// parseMcdataSignalling decodes the fixed head of an SDS SIGNALLING PAYLOAD
// or SDS NOTIFICATION message (clauses 15.1.2.1 and 15.1.5.1). Anything
// shorter than its mandatory part, or of another type, yields ok=false -
// clause 15's rule is to ignore what cannot be understood.
func parseMcdataSignalling(body []byte) (mcdataSignalling, bool) {
	if len(body) < 1 {
		return mcdataSignalling{}, false
	}
	// Bits 7-8 of the message type octet are spare (table 15.2.2-1).
	msgType := body[0] & 0x3f
	out := mcdataSignalling{MessageType: msgType}

	switch msgType {
	case mcdataSDSSignallingPayload, mcdataFDSignallingPayload, mcdataDataPayload:
		// type(1) + date-and-time(5) + conversation(16) + message(16)
		if len(body) < 1+5+16+16 {
			return mcdataSignalling{}, false
		}
		out.ConversationID = hex.EncodeToString(body[6:22])
		out.MessageID = hex.EncodeToString(body[22:38])
	case mcdataSDSNotification, mcdataFDNotification:
		// type(1) + notification-type(1) + date-and-time(5) +
		// conversation(16) + message(16)
		if len(body) < 1+1+5+16+16 {
			return mcdataSignalling{}, false
		}
		out.NotificationType = body[1]
		out.ConversationID = hex.EncodeToString(body[7:23])
		out.MessageID = hex.EncodeToString(body[23:39])
	default:
		return mcdataSignalling{}, false
	}
	return out, true
}

// dispositionTypeName renders a notification type for logs.
func dispositionTypeName(t byte) string {
	switch t {
	case mcdataDispositionDelivered:
		return "delivered"
	case mcdataDispositionRead:
		return "read"
	case mcdataDispositionDeliveredRead:
		return "delivered-and-read"
	case mcdataDispositionNotDeliverable:
		return "not-deliverable"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}

// sdsTransmission is what a disposition notification is correlated against
// (clause 12.2.3 step 4: the Conversation ID and Message ID of the original
// SDS request).
type sdsTransmission struct {
	originator string
	group      string
	at         time.Time
}

type sdsCorrelator struct {
	mu    sync.Mutex
	byKey map[string]sdsTransmission
}

func newSDSCorrelator() *sdsCorrelator {
	return &sdsCorrelator{byKey: map[string]sdsTransmission{}}
}

// remember records an SDS transmission so its dispositions can be correlated.
// Entries older than the retention window are swept opportunistically: a
// disposition that arrives after it is treated as uncorrelatable, which is
// what warning 216 exists for.
func (c *sdsCorrelator) remember(key string, tx sdsTransmission) {
	if strings.TrimSpace(key) == "/" || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	for k, v := range c.byKey {
		if now.Sub(v.at) > 24*time.Hour {
			delete(c.byKey, k)
		}
	}
	c.byKey[key] = tx
}

// lookup returns the remembered transmission for a correlation key.
func (c *sdsCorrelator) lookup(key string) (sdsTransmission, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, ok := c.byKey[key]
	return tx, ok
}

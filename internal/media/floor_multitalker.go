package media

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Multi-talker floor control, TS 24.380 clause 4.1.1.6 and 6.3.4.4.7a: when a
// group is configured as a multi-talker group, a floor request can be granted
// without revoking the current talker, up to the "maximum number of
// simultaneous talkers". The group-document element of TS 24.481 is stood in
// for by the multi_talker/max_simultaneous_talkers columns on the group
// record; an ad hoc group (no group record) stays single-talker until the
// service configuration document of TS 24.484 exists to carry the setting.

// Floor control field IDs, TS 24.380 table 8.2.3.1-2.
const (
	fldFloorPriority     = 0  // 8.2.3.2
	fldDuration          = 1  // 8.2.3.3
	fldRejectCause       = 2  // 8.2.3.4
	fldGrantedPartyID    = 4  // 8.2.3.6
	fldPermissionRequest = 5  // 8.2.3.7
	fldUserID            = 6  // 8.2.3.8
	fldTrackInfo         = 11 // 8.2.3.13
	fldFloorIndicator    = 13 // 8.2.3.15
	fldAudioSSRC         = 14 // 8.2.3.16
	fldGrantedUsers      = 15 // 8.2.3.17
	fldSSRCList          = 16 // 8.2.3.18
	fldFunctionalAlias   = 17 // 8.2.3.19
)

// Floor Indicator bits, table 8.2.3.15-2 (A is the most significant bit).
const (
	floorIndicatorNormal      = 0x8000 // A: Normal call
	floorIndicatorQueueing    = 0x0400 // F: Queueing supported
	floorIndicatorMultiTalker = 0x0080 // I: Multi-talker
)

// walkFloorFields iterates the application-specific data fields of a floor
// control message per clause 8.1.3: one-octet field ID, a length value that
// is one octet for IDs below 192 and two octets otherwise, the value, and
// zero-padding up to a four-octet boundary per field.
func walkFloorFields(data []byte, visit func(id byte, value []byte)) {
	for len(data) >= 2 {
		id := data[0]
		hdr := 2
		length := int(data[1])
		if id >= 192 {
			if len(data) < 3 {
				return
			}
			hdr = 3
			length = int(binary.BigEndian.Uint16(data[1:3]))
		}
		if hdr+length > len(data) {
			return
		}
		visit(id, data[hdr:hdr+length])
		total := hdr + length
		if rem := total % 4; rem != 0 {
			total += 4 - rem
		}
		if total > len(data) {
			return
		}
		data = data[total:]
	}
}

// appendFloorField appends one application-specific data field (ID below 192)
// with the clause 8.1.3 zero-padding to a four-octet boundary.
func appendFloorField(b []byte, id byte, value []byte) []byte {
	b = append(b, id, byte(len(value)))
	b = append(b, value...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// floorMessage assembles an RTCP APP "MCPT" message (clause 8.1.2) around the
// already-encoded application-specific data fields.
func floorMessage(subtype uint8, ssrc uint32, fields []byte) []byte {
	packet := make([]byte, 12, 12+len(fields))
	packet[0] = 0x80 | (subtype & 0x1f)
	packet[1] = rtcpPacketTypeAPP
	binary.BigEndian.PutUint32(packet[4:8], ssrc)
	copy(packet[8:12], "MCPT")
	packet = append(packet, fields...)
	binary.BigEndian.PutUint16(packet[2:4], uint16((len(packet)/4)-1))
	return packet
}

// encodeGrantedUsers encodes a List of Granted Users field value per clause
// 8.2.3.17: a one-octet entry count followed by <length, URI> pairs.
func encodeGrantedUsers(users []string) []byte {
	value := []byte{byte(len(users))}
	for _, u := range users {
		value = append(value, byte(len(u)))
		value = append(value, u...)
	}
	return value
}

// decodeGrantedUsers reverses encodeGrantedUsers, ignoring trailing padding.
func decodeGrantedUsers(value []byte) []string {
	if len(value) < 1 {
		return nil
	}
	count := int(value[0])
	value = value[1:]
	var users []string
	for i := 0; i < count && len(value) >= 1; i++ {
		l := int(value[0])
		if 1+l > len(value) {
			break
		}
		users = append(users, string(value[1:1+l]))
		value = value[1+l:]
	}
	return users
}

// encodeSSRCList encodes a List of SSRCs field value per clause 8.2.3.18: a
// one-octet count, one spare octet, then four-octet SSRC values.
func encodeSSRCList(ssrcs []uint32) []byte {
	value := make([]byte, 2, 2+4*len(ssrcs))
	value[0] = byte(len(ssrcs))
	for _, s := range ssrcs {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], s)
		value = append(value, b[:]...)
	}
	return value
}

// buildMCPTTFloorTaken builds a Floor Taken message (clause 8.2.9) toward a
// non-requesting participant: the granted party's identity, permission to
// request the floor, and the Floor Indicator. In a multi-talker scenario the
// I-bit is set and the List of Granted Users and List of SSRCs fields carry
// the full talker set (clause 6.3.4.4.7a).
func buildMCPTTFloorTaken(ssrc uint32, grantedID string, indicator uint16, grantedUsers []string, audioSSRCs []uint32) []byte {
	var fields []byte
	fields = appendFloorField(fields, fldGrantedPartyID, []byte(grantedID))
	fields = appendFloorField(fields, fldPermissionRequest, []byte{0, 1})
	var ind [2]byte
	binary.BigEndian.PutUint16(ind[:], indicator)
	fields = appendFloorField(fields, fldFloorIndicator, ind[:])
	if indicator&floorIndicatorMultiTalker != 0 {
		fields = appendFloorField(fields, fldGrantedUsers, encodeGrantedUsers(grantedUsers))
		fields = appendFloorField(fields, fldSSRCList, encodeSSRCList(audioSSRCs))
	}
	return floorMessage(mcpttFloorTaken, ssrc, fields)
}

// buildMCPTTFloorReleaseMultiTalker builds a Floor Release Multi Talker
// message (clause 8.2.14): the identity and SSRC of the participant that
// released while other talkers keep the floor, with the I-bit set.
func buildMCPTTFloorReleaseMultiTalker(userID string, participantSSRC uint32) []byte {
	var fields []byte
	fields = appendFloorField(fields, fldUserID, []byte(userID))
	var ind [2]byte
	binary.BigEndian.PutUint16(ind[:], floorIndicatorNormal|floorIndicatorMultiTalker)
	fields = appendFloorField(fields, fldFloorIndicator, ind[:])
	// The releasing participant's SSRC, coded as the Audio SSRC of Granted
	// Participant field (length 6: the SSRC plus two spare octets).
	var ssrcVal [6]byte
	binary.BigEndian.PutUint32(ssrcVal[:4], participantSSRC)
	fields = appendFloorField(fields, fldAudioSSRC, ssrcVal[:])
	return floorMessage(mcpttFloorReleaseMultiTalker, serverFloorSSRC, fields)
}

// groupFloorPolicy resolves the multi-talker configuration for a group URI.
// The default maximum of 2 applies when the group is marked multi-talker
// without an explicit limit.
func (o *Observer) groupFloorPolicy(ctx context.Context, groupURI string) (bool, int) {
	if strings.TrimSpace(groupURI) == "" {
		return false, 1
	}
	groups, err := o.st.ListGroups(ctx)
	if err != nil {
		slog.Warn("MCPTT floor policy lookup failed", "group_uri", groupURI, "err", err)
		return false, 1
	}
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g.URI), strings.TrimSpace(groupURI)) {
			if !g.MultiTalker {
				return false, 1
			}
			max := g.MaxSimultaneousTalkers
			if max < 2 {
				max = 2
			}
			return true, max
		}
	}
	return false, 1
}

// grantedTalkerLegs returns the group legs currently holding the floor
// (clause 6.3.4.3.3: the list of currently granted talkers), keyed off the
// per-leg floor state the observer maintains.
func grantedTalkerLegs(peers []store.MCPTTCall) []store.MCPTTCall {
	var talkers []store.MCPTTCall
	for _, p := range peers {
		if strings.TrimSpace(p.FloorHolder) == "" {
			continue
		}
		switch p.FloorState {
		case "granted", "taken":
			talkers = append(talkers, p)
		}
	}
	return talkers
}

// floorArbitrate decides whether a floor request on `call` may be granted
// given the other legs' floor state: single-talker refuses while any other
// leg holds the floor; multi-talker grants while the talker count stays
// within the maximum (clause 6.3.4.4.7a case b), refusing at the limit
// (case a's revoke-by-priority alternative is not applied - the request is
// denied, which the clause allows when priorities do not differ).
func floorArbitrate(call store.MCPTTCall, otherTalkers int, multiTalker bool, maxTalkers int) bool {
	if !multiTalker {
		return otherTalkers == 0
	}
	return otherTalkers+1 <= maxTalkers
}

// legUser is the MCPTT user behind a call leg: the initiator on the
// client-originated TX leg, the invited member on an AS-initiated RX leg.
func (o *Observer) legUser(call store.MCPTTCall) string {
	if strings.EqualFold(strings.TrimSpace(call.InitiatorURI), strings.TrimSpace(o.cfg.MCX.SIPIdentity)) {
		return strings.TrimSpace(call.TargetURI)
	}
	return strings.TrimSpace(call.InitiatorURI)
}

// notifyFloorPeers sends a floor control message to every other group leg
// with a negotiated floor control address.
func (o *Observer) notifyFloorPeers(pc net.PacketConn, peers []store.MCPTTCall, excludeCallID string, packet []byte) {
	for _, peer := range peers {
		if peer.CallID == excludeCallID {
			continue
		}
		if strings.TrimSpace(peer.FloorControlIP) == "" || peer.FloorControlPort == 0 {
			continue
		}
		dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(peer.FloorControlIP, strconv.Itoa(peer.FloorControlPort)))
		if err != nil {
			slog.Warn("MCPTT floor notify address resolve failed", "peer_call_id", peer.CallID, "err", err)
			continue
		}
		if _, err := pc.WriteTo(packet, dst); err != nil {
			slog.Warn("MCPTT floor notify send failed", "peer_call_id", peer.CallID, "dst", dst, "err", err)
		}
	}
}

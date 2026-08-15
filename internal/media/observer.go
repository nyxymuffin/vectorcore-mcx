package media

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

type Store interface {
	ListCalls(context.Context) ([]store.MCPTTCall, error)
	ListCallsByGroup(context.Context, string) ([]store.MCPTTCall, error)
	ListGroups(context.Context) ([]store.Group, error)
	IncrementCallMedia(context.Context, string, string, int) error
	UpdateCallRTPStats(context.Context, string, store.RTPStatsUpdate) error
	UpdateCallFloorState(context.Context, string, store.FloorStateUpdate) (bool, error)
}

type Observer struct {
	cfg    config.Config
	st     Store
	queues *floorQueues
}

func NewObserver(cfg config.Config, st Store) *Observer {
	return &Observer{cfg: cfg, st: st, queues: newFloorQueues()}
}

func (o *Observer) Start(ctx context.Context) error {
	if !o.cfg.Media.Enabled {
		<-ctx.Done()
		return nil
	}
	errCh := make(chan error, 3)
	go func() { errCh <- o.listen(ctx, "rtp", o.cfg.Media.AudioPort) }()
	go func() { errCh <- o.listen(ctx, "rtcp", o.cfg.Media.RTCPPort) }()
	go func() { errCh <- o.listen(ctx, "floor", o.cfg.Media.FloorControlPort) }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (o *Observer) listen(ctx context.Context, kind string, port int) error {
	if port <= 0 {
		<-ctx.Done()
		return nil
	}
	addr := net.JoinHostPort(o.cfg.Media.ListenHost, strconv.Itoa(port))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()
	slog.Info("MCPTT media observer listening", "kind", kind, "addr", addr)
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		packet := append([]byte(nil), buf[:n]...)
		o.recordPacket(ctx, pc, kind, remote, packet)
	}
}

func (o *Observer) recordPacket(ctx context.Context, pc net.PacketConn, kind string, remote net.Addr, packet []byte) {
	remoteText := remote.String()
	call, matched, err := o.matchCall(ctx, kind, remoteText)
	if err != nil {
		slog.Warn("MCPTT media match failed", "kind", kind, "remote", remoteText, "err", err)
		return
	}
	if !matched {
		slog.Debug("MCPTT media packet unmatched", "kind", kind, "remote", remoteText, "bytes", len(packet), "sample", packetSample(packet))
		return
	}
	if kind == "rtp" {
		header, ok := parseRTPHeader(packet)
		if ok && !rtpAuthorizedForFloor(call, header.SSRC) {
			if err := o.st.IncrementCallMedia(ctx, call.CallID, "rtp_rejected", len(packet)); err != nil {
				slog.Warn("MCPTT rejected RTP counter update failed", "call_id", call.CallID, "remote", remoteText, "ssrc", header.SSRC, "holder", call.FloorHolder, "err", err)
			}
			slog.Warn("MCPTT RTP rejected", "call_id", call.CallID, "remote", remoteText, "ssrc", header.SSRC, "floor_holder", call.FloorHolder)
			return
		}
		if err := o.st.IncrementCallMedia(ctx, call.CallID, kind, len(packet)); err != nil {
			slog.Warn("MCPTT media counter update failed", "kind", kind, "call_id", call.CallID, "remote", remoteText, "err", err)
			return
		}
		if stats, ok := rtpStatsFromPacket(packet, call, time.Now().UTC()); ok {
			if err := o.st.UpdateCallRTPStats(ctx, call.CallID, stats); err != nil {
				slog.Warn("MCPTT RTP stats update failed", "call_id", call.CallID, "remote", remoteText, "err", err)
			}
		}
		o.relayRTP(ctx, pc, call, packet)
		o.logPacket(kind, call, remoteText, packet)
		return
	}
	if err := o.st.IncrementCallMedia(ctx, call.CallID, kind, len(packet)); err != nil {
		slog.Warn("MCPTT media counter update failed", "kind", kind, "call_id", call.CallID, "remote", remoteText, "err", err)
		return
	}
	if kind == "floor" {
		if event, ok := parseMCPTTFloorEvent(packet); ok {
			eventName := floorEventName(event.Subtype)
			floorState := floorStateForEvent(event.Subtype, call.FloorState)
			clearHolder := floorClearsHolder(floorState) && floorCanClearHolder(call, event.SSRC)
			if _, err := o.st.UpdateCallFloorState(ctx, call.CallID, store.FloorStateUpdate{
				State:       floorState,
				Event:       eventName,
				Subtype:     int(event.Subtype),
				SSRC:        event.SSRC,
				Holder:      floorHolderForUpdate(event, floorState, call.FloorHolder, clearHolder),
				ClearHolder: clearHolder,
			}); err != nil {
				slog.Warn("MCPTT floor state update failed", "call_id", call.CallID, "remote", remoteText, "event", eventName, "err", err)
			}
			slog.Info("MCPTT floor event", "call_id", call.CallID, "remote", remoteText, "event", eventName, "state", floorState, "subtype", event.Subtype, "ssrc", event.SSRC)
			if event.Subtype == mcpttFloorRelease && o.cfg.Media.FloorAutoGrant && clearHolder {
				// TS 24.380 clause 6.3.4.4.4/6.3.4.4.8: after a release the
				// server tells the releaser (and the other participants) that
				// the floor is idle - unless the group is multi-talker and
				// other talkers keep the floor, in which case a Floor Release
				// Multi Talker message (clause 8.2.14) announces just this
				// participant's release.
				multiTalker, _ := o.groupFloorPolicy(ctx, call.GroupURI)
				var peers []store.MCPTTCall
				if strings.TrimSpace(call.GroupURI) != "" {
					peers, _ = o.st.ListCallsByGroup(ctx, call.GroupURI)
				}
				remaining := 0
				for _, talker := range grantedTalkerLegs(peers) {
					if talker.CallID != call.CallID {
						remaining++
					}
				}
				var response []byte
				if multiTalker && remaining > 0 {
					response = buildMCPTTFloorReleaseMultiTalker(event.SSRC, o.legUser(call), event.SSRC)
				} else {
					response = buildMCPTTFloorIdle(event.SSRC)
				}
				if _, err := pc.WriteTo(response, remote); err != nil {
					slog.Warn("MCPTT floor idle send failed", "call_id", call.CallID, "remote", remoteText, "err", err)
				} else {
					if _, err := o.st.UpdateCallFloorState(ctx, call.CallID, store.FloorStateUpdate{
						State:       "idle",
						Event:       floorEventName(mcpttFloorIdle),
						Subtype:     mcpttFloorIdle,
						SSRC:        event.SSRC,
						ClearHolder: true,
					}); err != nil {
						slog.Warn("MCPTT floor idle state update failed", "call_id", call.CallID, "remote", remoteText, "err", err)
					}
					slog.Info("MCPTT floor idle", "call_id", call.CallID, "remote", remoteText, "multi_talker_remaining", remaining)
				}
				o.notifyFloorPeers(pc, peers, call.CallID, response)
				// A freed floor goes to the head of the request queue
				// (clause 6.3.4.4.4).
				o.queues.remove(queueKey(call), call.CallID)
				o.grantQueuedRequest(ctx, pc, call)
				return
			}
			if event.Subtype == mcpttQueuePositionReq && o.cfg.Media.FloorAutoGrant {
				// Clause 8.2.11/8.2.12: report the requester's actual queue
				// position; 254 means not queued (clause 8.2.3.5).
				pos := o.queues.position(queueKey(call), call.CallID, event.SSRC)
				positionValue := uint8(queuePositionNotQueued)
				if pos > 0 {
					positionValue = uint8(pos)
				}
				response := buildMCPTTQueuePositionInfo(event.SSRC, positionValue, 0)
				if _, err := pc.WriteTo(response, remote); err != nil {
					slog.Warn("MCPTT queue position send failed", "call_id", call.CallID, "remote", remoteText, "err", err)
				} else {
					if _, err := o.st.UpdateCallFloorState(ctx, call.CallID, store.FloorStateUpdate{
						State:   valueOr(call.FloorState, "queued"),
						Event:   floorEventName(mcpttQueuePosition),
						Subtype: mcpttQueuePosition,
						SSRC:    event.SSRC,
						Holder:  call.FloorHolder,
					}); err != nil {
						slog.Warn("MCPTT queue position state update failed", "call_id", call.CallID, "remote", remoteText, "err", err)
					}
					slog.Info("MCPTT queue position", "call_id", call.CallID, "remote", remoteText, "holder", call.FloorHolder)
				}
				return
			}
			if event.Subtype == mcpttFloorRequest && o.cfg.Media.FloorAutoGrant && call.State != "terminated" && call.State != "cancelled" {
				// Group-wide arbitration (TS 24.380 clause 6.3.4.4.2 /
				// 6.3.4.4.7a): a single-talker group refuses while any other
				// leg holds the floor; a multi-talker group grants until the
				// maximum number of simultaneous talkers is reached.
				multiTalker, maxTalkers := o.groupFloorPolicy(ctx, call.GroupURI)
				var peers []store.MCPTTCall
				if strings.TrimSpace(call.GroupURI) != "" {
					peers, _ = o.st.ListCallsByGroup(ctx, call.GroupURI)
				}
				otherTalkers := []store.MCPTTCall{}
				for _, talker := range grantedTalkerLegs(peers) {
					if talker.CallID != call.CallID {
						otherTalkers = append(otherTalkers, talker)
					}
				}
				// Claim the floor before announcing it. floorCanGrant decides
				// from a snapshot read moments ago, so two requests from
				// different SSRCs can both reach here believing the floor is
				// free. The guarded update applies only while the holder is
				// still what the decision assumed, so exactly one wins and the
				// loser is denied rather than being granted a floor it does
				// not hold.
				granted := false
				if floorCanGrant(call, event.SSRC) && floorArbitrate(call, len(otherTalkers), multiTalker, maxTalkers) {
					expected := call.FloorHolder
					applied, err := o.st.UpdateCallFloorState(ctx, call.CallID, store.FloorStateUpdate{
						State:        "granted",
						Event:        floorEventName(mcpttFloorGranted),
						Subtype:      mcpttFloorGranted,
						SSRC:         event.SSRC,
						Holder:       floorHolder(event.SSRC),
						ExpectHolder: &expected,
					})
					if err != nil {
						slog.Warn("MCPTT floor grant state update failed", "call_id", call.CallID, "remote", remoteText, "err", err)
					} else if !applied {
						slog.Info("MCPTT floor grant lost race", "call_id", call.CallID, "remote", remoteText, "expected_holder", expected)
					}
					granted = err == nil && applied
				}
				if !granted {
					// TS 24.380 clause 6.3.4.4.2 case b: a client that
					// negotiated queueing (mc_queueing, clause 14.2.2) is
					// queued instead of denied and told its position.
					if negotiatedQueueing(call) {
						priority := uint8(0)
						if event.HasPriority {
							priority = event.Priority
						}
						if pos := o.queues.enqueue(queueKey(call), queuedFloorRequest{
							callID: call.CallID, ssrc: event.SSRC, remote: remoteText, priority: priority,
						}); pos > 0 {
							response := buildMCPTTQueuePositionInfo(event.SSRC, uint8(pos), priority)
							if _, err := pc.WriteTo(response, remote); err != nil {
								slog.Warn("MCPTT queue position info send failed", "call_id", call.CallID, "remote", remoteText, "err", err)
							} else {
								if _, err := o.st.UpdateCallFloorState(ctx, call.CallID, store.FloorStateUpdate{
									State:   "queued",
									Event:   floorEventName(mcpttQueuePosition),
									Subtype: mcpttQueuePosition,
									SSRC:    event.SSRC,
									Holder:  call.FloorHolder,
								}); err != nil {
									slog.Warn("MCPTT queue state update failed", "call_id", call.CallID, "err", err)
								}
								slog.Info("MCPTT floor request queued", "call_id", call.CallID, "position", pos, "priority", priority)
							}
							return
						}
						// Queue full: fall through to the deny.
					}
					response := buildMCPTTFloorDeny(event.SSRC)
					if _, err := pc.WriteTo(response, remote); err != nil {
						slog.Warn("MCPTT floor deny send failed", "call_id", call.CallID, "remote", remoteText, "err", err)
					} else {
						if _, err := o.st.UpdateCallFloorState(ctx, call.CallID, store.FloorStateUpdate{
							State:   valueOr(call.FloorState, "denied"),
							Event:   floorEventName(mcpttFloorDeny),
							Subtype: mcpttFloorDeny,
							SSRC:    event.SSRC,
							Holder:  call.FloorHolder,
						}); err != nil {
							slog.Warn("MCPTT floor deny state update failed", "call_id", call.CallID, "remote", remoteText, "err", err)
						}
						slog.Info("MCPTT floor denied", "call_id", call.CallID, "remote", remoteText, "holder", call.FloorHolder)
					}
					return
				}
				// The floor is now held in the store, so announce it.
				indicator := uint16(floorIndicatorNormal)
				if multiTalker {
					indicator |= floorIndicatorMultiTalker
				}
				response := buildMCPTTFloorGranted(event.SSRC, o.cfg.Media.FloorGrantDurationSeconds, indicator)
				if _, err := pc.WriteTo(response, remote); err != nil {
					slog.Warn("MCPTT floor grant send failed", "call_id", call.CallID, "remote", remoteText, "err", err)
				} else {
					slog.Info("MCPTT floor granted", "call_id", call.CallID, "remote", remoteText, "duration", o.cfg.Media.FloorGrantDurationSeconds, "multi_talker", multiTalker, "talkers", len(otherTalkers)+1)
				}
				// TS 24.380 clause 6.3.4.4.2 item c (and 6.3.4.4.7a item c for
				// multi-talker): the other participants learn of the grant
				// through a Floor Taken message; in the multi-talker case it
				// carries the full talker set in the List of Granted Users and
				// List of SSRCs fields.
				grantedUsers := []string{o.legUser(call)}
				audioSSRCs := []uint32{event.SSRC}
				for _, talker := range otherTalkers {
					grantedUsers = append(grantedUsers, o.legUser(talker))
					audioSSRCs = append(audioSSRCs, talker.FloorSSRC)
				}
				taken := buildMCPTTFloorTaken(event.SSRC, o.legUser(call), indicator, grantedUsers, audioSSRCs)
				o.notifyFloorPeers(pc, peers, call.CallID, taken)
			}
		} else {
			slog.Debug("MCPTT floor packet received", "call_id", call.CallID, "remote", remoteText, "bytes", len(packet), "sample", packetSample(packet))
		}
		return
	}
	o.logPacket(kind, call, remoteText, packet)
}

func (o *Observer) logPacket(kind string, call store.MCPTTCall, remote string, packet []byte) {
	if !o.cfg.Media.LogPackets {
		return
	}
	interval := o.cfg.Media.LogPacketInterval
	if interval <= 0 {
		interval = 100
	}
	var count int64
	switch kind {
	case "rtp":
		count = call.RTPPackets + 1
	case "rtcp":
		count = call.RTCPPackets + 1
	case "floor":
		count = call.FloorPackets + 1
	}
	if count <= 1 || count%interval == 0 {
		slog.Debug("MCPTT media packet received", "kind", kind, "call_id", call.CallID, "remote", remote, "packets", count, "bytes", len(packet), "sample", packetSample(packet))
	}
}

func (o *Observer) relayRTP(ctx context.Context, pc net.PacketConn, txCall store.MCPTTCall, packet []byte) {
	if strings.TrimSpace(txCall.GroupURI) == "" {
		return
	}
	peers, err := o.st.ListCallsByGroup(ctx, txCall.GroupURI)
	if err != nil {
		slog.Warn("MCPTT RTP relay peer lookup failed", "call_id", txCall.CallID, "group_uri", txCall.GroupURI, "err", err)
		return
	}
	for _, peer := range peers {
		if peer.CallID == txCall.CallID {
			continue
		}
		if strings.TrimSpace(peer.AudioIP) == "" || peer.AudioPort == 0 {
			continue
		}
		// Never relay audio back to the same IP that sent it: prevents echoing
		// when a stale call record from a previous session shares the TX device's IP.
		if hostMatches(peer.AudioIP, txCall.AudioIP) {
			continue
		}
		dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(peer.AudioIP, strconv.Itoa(peer.AudioPort)))
		if err != nil {
			slog.Warn("MCPTT RTP relay address resolve failed", "call_id", txCall.CallID, "peer_call_id", peer.CallID, "audio_ip", peer.AudioIP, "audio_port", peer.AudioPort, "err", err)
			continue
		}
		if _, err := pc.WriteTo(packet, dst); err != nil {
			slog.Warn("MCPTT RTP relay send failed", "call_id", txCall.CallID, "peer_call_id", peer.CallID, "dst", dst, "err", err)
		} else {
			slog.Debug("MCPTT RTP relayed", "call_id", txCall.CallID, "peer_call_id", peer.CallID, "group_uri", txCall.GroupURI, "dst", dst, "bytes", len(packet))
		}
	}
}

func (o *Observer) matchCall(ctx context.Context, kind, remote string) (store.MCPTTCall, bool, error) {
	host, portText, err := net.SplitHostPort(remote)
	if err != nil {
		return store.MCPTTCall{}, false, err
	}
	port, _ := strconv.Atoi(portText)
	calls, err := o.st.ListCalls(ctx)
	if err != nil {
		return store.MCPTTCall{}, false, err
	}
	// Two-pass: exact IP+port match first, then IP-only fallback.
	// The IP-only fallback handles UEs that send RTP from an ephemeral port
	// different from the port declared in their SDP offer (asymmetric RTP).
	var ipFallback *store.MCPTTCall
	for _, call := range calls {
		if call.State == "cancelled" {
			continue
		}
		if call.State == "terminated" && !allowPostTerminateMedia(kind, call) {
			continue
		}
		switch kind {
		case "rtp":
			if hostMatches(call.AudioIP, host) {
				if call.AudioPort == 0 || call.AudioPort == port {
					return call, true, nil
				}
				if ipFallback == nil {
					c := call
					ipFallback = &c
				}
			}
		case "rtcp":
			if hostMatches(call.AudioIP, host) && (call.AudioPort == 0 || call.AudioPort+1 == port || call.AudioPort == port) {
				return call, true, nil
			}
		case "floor":
			if hostMatches(call.FloorControlIP, host) && (call.FloorControlPort == 0 || call.FloorControlPort == port) {
				return call, true, nil
			}
		default:
			return store.MCPTTCall{}, false, fmt.Errorf("unknown media kind %q", kind)
		}
	}
	if kind == "rtp" && ipFallback != nil {
		slog.Debug("MCPTT RTP matched by IP only (asymmetric port)", "call_id", ipFallback.CallID, "remote", remote, "sdp_port", ipFallback.AudioPort)
		return *ipFallback, true, nil
	}
	return store.MCPTTCall{}, false, nil
}

func allowPostTerminateMedia(kind string, call store.MCPTTCall) bool {
	if kind != "rtcp" && kind != "floor" {
		return false
	}
	terminatedAt := call.TerminatedAt
	if terminatedAt.IsZero() {
		terminatedAt = call.UpdatedAt
	}
	return !terminatedAt.IsZero() && time.Since(terminatedAt) <= 5*time.Second
}

func hostMatches(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	return a == b
}

// Floor control message subtypes, TS 24.380 table 8.2.2.1-1 (the
// acknowledgment-request x bit masked off).
const (
	rtcpPacketTypeAPP            = 204
	mcpttFloorRequest            = 0
	mcpttFloorGranted            = 1
	mcpttFloorTaken              = 2
	mcpttFloorDeny               = 3
	mcpttFloorRelease            = 4
	mcpttFloorIdle               = 5
	mcpttFloorRevoke             = 6
	mcpttFloorRevokeRequest      = 7
	mcpttQueuePositionReq        = 8
	mcpttQueuePosition           = 9
	mcpttFloorAck                = 10
	mcpttUnicastMediaFlowControl = 11
	mcpttQueuedFloorRequests     = 14
	mcpttFloorReleaseMultiTalker = 15
	mcpttNormalCall              = floorIndicatorNormal
	rtpClockRate                 = 8000
)

type rtpHeader struct {
	PayloadType int
	Sequence    uint16
	Timestamp   uint32
	SSRC        uint32
}

func parseRTPHeader(packet []byte) (rtpHeader, bool) {
	if len(packet) < 12 {
		return rtpHeader{}, false
	}
	if packet[0]>>6 != 2 {
		return rtpHeader{}, false
	}
	csrcCount := int(packet[0] & 0x0f)
	headerLen := 12 + csrcCount*4
	if len(packet) < headerLen {
		return rtpHeader{}, false
	}
	return rtpHeader{
		PayloadType: int(packet[1] & 0x7f),
		Sequence:    binary.BigEndian.Uint16(packet[2:4]),
		Timestamp:   binary.BigEndian.Uint32(packet[4:8]),
		SSRC:        binary.BigEndian.Uint32(packet[8:12]),
	}, true
}

func rtpStatsFromPacket(packet []byte, call store.MCPTTCall, now time.Time) (store.RTPStatsUpdate, bool) {
	h, ok := parseRTPHeader(packet)
	if !ok {
		return store.RTPStatsUpdate{}, false
	}
	packets := call.RTPPackets + 1
	firstSeq := call.RTPFirstSequence
	lastSeq := call.RTPLastSequence
	cycles := call.RTPSequenceCycles
	jitter := call.RTPJitter

	if call.RTPPackets == 0 || call.RTPSSRC != 0 && call.RTPSSRC != h.SSRC {
		firstSeq = h.Sequence
		cycles = 0
		jitter = 0
	} else {
		if h.Sequence < lastSeq && lastSeq-h.Sequence > 30000 {
			cycles++
		}
		jitter = updateJitter(call, h.Timestamp, now)
	}

	extendedLast := cycles*65536 + int64(h.Sequence)
	expected := extendedLast - int64(firstSeq) + 1
	if expected < packets {
		expected = packets
	}
	lost := expected - packets
	if lost < 0 {
		lost = 0
	}

	return store.RTPStatsUpdate{
		PayloadType:     h.PayloadType,
		SSRC:            h.SSRC,
		FirstSequence:   firstSeq,
		LastSequence:    h.Sequence,
		LastTimestamp:   h.Timestamp,
		SequenceCycles:  cycles,
		ExpectedPackets: expected,
		LostPackets:     lost,
		Jitter:          jitter,
	}, true
}

func updateJitter(call store.MCPTTCall, timestamp uint32, now time.Time) float64 {
	if call.LastRTPAt.IsZero() {
		return call.RTPJitter
	}
	arrivalDelta := float64(now.Sub(call.LastRTPAt).Nanoseconds()) * rtpClockRate / 1e9
	rtpDelta := float64(int32(timestamp - call.RTPLastTimestamp))
	d := arrivalDelta - rtpDelta
	if d < 0 {
		d = -d
	}
	return call.RTPJitter + (d-call.RTPJitter)/16
}

func rtpAuthorizedForFloor(call store.MCPTTCall, ssrc uint32) bool {
	holder := strings.TrimSpace(call.FloorHolder)
	if holder == "" {
		return true
	}
	return holder == floorHolder(ssrc)
}

type floorEvent struct {
	Subtype uint8
	SSRC    uint32
	// Parsed application-specific data fields (clause 8.1.3), where present.
	Priority     uint8
	HasPriority  bool
	Indicator    uint16
	HasIndicator bool
	UserID       string
	GrantedUsers []string
}

func floorEventName(subtype uint8) string {
	switch subtype {
	case mcpttFloorRequest:
		return "request"
	case mcpttFloorGranted:
		return "granted"
	case mcpttFloorTaken:
		return "taken"
	case mcpttFloorDeny:
		return "denied"
	case mcpttFloorRelease:
		return "release"
	case mcpttFloorIdle:
		return "idle"
	case mcpttFloorRevoke:
		return "revoked"
	case mcpttQueuePositionReq:
		return "queue_position_request"
	case mcpttQueuePosition:
		return "queue_position"
	case mcpttFloorAck:
		return "ack"
	case mcpttFloorRevokeRequest:
		return "revoke_request"
	case mcpttUnicastMediaFlowControl:
		return "unicast_media_flow_control"
	case mcpttQueuedFloorRequests:
		return "queued_floor_requests"
	case mcpttFloorReleaseMultiTalker:
		return "release_multi_talker"
	default:
		return fmt.Sprintf("subtype_%d", subtype)
	}
}

func floorStateForEvent(subtype uint8, current string) string {
	switch subtype {
	case mcpttFloorRequest:
		return "requested"
	case mcpttFloorGranted:
		return "granted"
	case mcpttFloorTaken:
		return "taken"
	case mcpttFloorDeny:
		return "denied"
	case mcpttFloorRelease:
		return "released"
	case mcpttFloorIdle:
		return "idle"
	case mcpttFloorRevoke:
		return "revoked"
	case mcpttQueuePositionReq, mcpttQueuePosition:
		if strings.TrimSpace(current) != "" {
			return current
		}
		return "queued"
	default:
		if strings.TrimSpace(current) != "" {
			return current
		}
		return "unknown"
	}
}

func floorCanGrant(call store.MCPTTCall, requestSSRC uint32) bool {
	holder := strings.TrimSpace(call.FloorHolder)
	if holder == "" {
		return true
	}
	if holder == floorHolder(requestSSRC) {
		return true
	}
	switch call.FloorState {
	case "", "idle", "released", "revoked", "denied":
		return true
	default:
		return false
	}
}

func floorHolderForUpdate(event floorEvent, state, currentHolder string, clearHolder bool) string {
	switch state {
	case "granted", "taken":
		return floorHolder(event.SSRC)
	case "released", "idle", "revoked":
		if clearHolder {
			return ""
		}
		return currentHolder
	case "denied":
		return currentHolder
	default:
		return ""
	}
}

func floorClearsHolder(state string) bool {
	switch state {
	case "released", "idle", "revoked":
		return true
	default:
		return false
	}
}

func floorCanClearHolder(call store.MCPTTCall, ssrc uint32) bool {
	holder := strings.TrimSpace(call.FloorHolder)
	return holder == "" || holder == floorHolder(ssrc)
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func floorHolder(ssrc uint32) string {
	if ssrc == 0 {
		return ""
	}
	return fmt.Sprintf("ssrc:%08x", ssrc)
}

func parseMCPTTFloorEvent(packet []byte) (floorEvent, bool) {
	if len(packet) < 12 {
		return floorEvent{}, false
	}
	if packet[0]>>6 != 2 || packet[1] != rtcpPacketTypeAPP {
		return floorEvent{}, false
	}
	if string(packet[8:12]) != "MCPT" {
		return floorEvent{}, false
	}
	// The x bit of the subtype only asks for an acknowledgment
	// (table 8.2.2.1-1); the low four bits identify the message.
	event := floorEvent{
		Subtype: packet[0] & 0x0f,
		SSRC:    binary.BigEndian.Uint32(packet[4:8]),
	}
	walkFloorFields(packet[12:], func(id byte, value []byte) {
		switch id {
		case fldFloorPriority:
			if len(value) >= 1 {
				event.Priority = value[0]
				event.HasPriority = true
			}
		case fldFloorIndicator:
			if len(value) >= 2 {
				event.Indicator = binary.BigEndian.Uint16(value[:2])
				event.HasIndicator = true
			}
		case fldUserID:
			event.UserID = string(value)
		case fldGrantedUsers:
			event.GrantedUsers = decodeGrantedUsers(value)
		}
	})
	return event, true
}

func buildMCPTTFloorGranted(ssrc uint32, durationSeconds int, indicator uint16) []byte {
	if durationSeconds < 1 {
		durationSeconds = 30
	}
	if durationSeconds > 65535 {
		durationSeconds = 65535
	}
	var fields []byte
	var dur [2]byte
	binary.BigEndian.PutUint16(dur[:], uint16(durationSeconds))
	fields = appendFloorField(fields, fldDuration, dur[:])
	var ind [2]byte
	binary.BigEndian.PutUint16(ind[:], indicator)
	fields = appendFloorField(fields, fldFloorIndicator, ind[:])
	return floorMessage(mcpttFloorGranted, ssrc, fields)
}

func buildMCPTTFloorDeny(ssrc uint32) []byte {
	packet := make([]byte, 12)
	packet[0] = 0x80 | mcpttFloorDeny
	packet[1] = rtcpPacketTypeAPP
	binary.BigEndian.PutUint16(packet[2:4], uint16((len(packet)/4)-1))
	binary.BigEndian.PutUint32(packet[4:8], ssrc)
	copy(packet[8:12], "MCPT")
	return packet
}

func buildMCPTTFloorIdle(ssrc uint32) []byte {
	packet := make([]byte, 12)
	packet[0] = 0x80 | mcpttFloorIdle
	packet[1] = rtcpPacketTypeAPP
	binary.BigEndian.PutUint16(packet[2:4], uint16((len(packet)/4)-1))
	binary.BigEndian.PutUint32(packet[4:8], ssrc)
	copy(packet[8:12], "MCPT")
	return packet
}

func buildMCPTTQueuePosition(ssrc uint32) []byte {
	packet := make([]byte, 12)
	packet[0] = 0x80 | mcpttQueuePosition
	packet[1] = rtcpPacketTypeAPP
	binary.BigEndian.PutUint16(packet[2:4], uint16((len(packet)/4)-1))
	binary.BigEndian.PutUint32(packet[4:8], ssrc)
	copy(packet[8:12], "MCPT")
	return packet
}

func packetSample(packet []byte) string {
	if len(packet) > 32 {
		packet = packet[:32]
	}
	return hex.EncodeToString(packet)
}

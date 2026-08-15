package sip

import (
	"fmt"
	"strconv"
	"strings"
)

// Media anchoring at the participating MCPTT function, TS 24.379 clause
// 6.3.2.1.2.1: when composing the SDP answer the participating function
// replaces the IP address and port of the accepted media stream (step 1) and
// of the media plane control channel (step 2) with its own, so the media and
// floor control of a relayed session traverse this server instead of flowing
// directly between the client and the remote controlling function.
//
// NOTE 3 of the clause allows the replacement to be omitted when the
// participating and controlling functions are the same server without
// dedicated media addresses - which is why locally homed calls, where this
// server is both, keep their existing SDP handling. Anchoring is applied to
// the relayed path, where the two functions are genuinely different systems.

// anchorSDP rewrites the connection address and the audio / MCPTT media
// ports of an SDP body to this server's media endpoints, leaving codecs,
// direction and every other attribute untouched.
func anchorSDP(sdp, host string, audioPort, floorPort int) string {
	if strings.TrimSpace(sdp) == "" || strings.TrimSpace(host) == "" {
		return sdp
	}
	lines := strings.Split(sdp, "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(trimmed, "c=IN IP4 "), strings.HasPrefix(trimmed, "c=IN IP6 "):
			family := "IP4"
			if strings.HasPrefix(trimmed, "c=IN IP6 ") {
				family = "IP6"
			}
			lines[i] = restoreCR(line, fmt.Sprintf("c=IN %s %s", family, host))
		case strings.HasPrefix(trimmed, "m=audio "):
			lines[i] = restoreCR(line, rewriteMediaPort(trimmed, audioPort))
		case strings.HasPrefix(trimmed, "m=application "):
			lines[i] = restoreCR(line, rewriteMediaPort(trimmed, floorPort))
		case strings.HasPrefix(trimmed, "o="):
			// The origin's unicast address is informational; keeping the
			// original is harmless, but pointing it at this server avoids
			// leaking the far end's address.
			if fields := strings.Fields(trimmed); len(fields) == 6 {
				fields[5] = host
				lines[i] = restoreCR(line, strings.Join(fields, " "))
			}
		}
	}
	return strings.Join(lines, "\n")
}

// restoreCR keeps the original line's CRLF style.
func restoreCR(original, replacement string) string {
	if strings.HasSuffix(original, "\r") {
		return replacement + "\r"
	}
	return replacement
}

// rewriteMediaPort replaces the port of an m= line, keeping the media type,
// transport and format list.
func rewriteMediaPort(mline string, port int) string {
	if port <= 0 {
		return mline
	}
	fields := strings.Fields(mline)
	if len(fields) < 3 {
		return mline
	}
	fields[1] = strconv.Itoa(port)
	return strings.Join(fields, " ")
}

// mediaAnchorHost is the address this server advertises for anchored media.
func (s *Server) mediaAnchorHost() string {
	if v := strings.TrimSpace(s.cfg.Media.AdvertiseHost); v != "" {
		return v
	}
	if v := strings.TrimSpace(s.cfg.SIP.AdvertiseHost); v != "" {
		return v
	}
	return "127.0.0.1"
}

// mediaAnchorPorts returns the audio and floor control ports to advertise.
func (s *Server) mediaAnchorPorts() (int, int) {
	audio := s.cfg.Media.AudioPort
	if audio == 0 {
		audio = 40000
	}
	floor := s.cfg.Media.FloorControlPort
	if floor == 0 {
		floor = 40002
	}
	return audio, floor
}

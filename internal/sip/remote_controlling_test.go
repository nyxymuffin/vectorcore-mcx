package sip

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

// fakeRemoteControlling captures what a remote controlling function receives.
type fakeRemoteControlling struct {
	sock net.PacketConn
	got  chan []byte
}

func newFakeRemote(t *testing.T) *fakeRemoteControlling {
	t.Helper()
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	f := &fakeRemoteControlling{sock: sock, got: make(chan []byte, 8)}
	go func() {
		buf := make([]byte, 16384)
		for {
			n, _, err := sock.ReadFrom(buf)
			if err != nil {
				return
			}
			f.got <- append([]byte(nil), buf[:n]...)
		}
	}()
	return f
}

func (f *fakeRemoteControlling) addr() string { return f.sock.LocalAddr().String() }

func (f *fakeRemoteControlling) receive(t *testing.T) *Message {
	t.Helper()
	select {
	case raw := <-f.got:
		msg, err := Parse(raw)
		if err != nil {
			t.Fatalf("fake remote could not parse: %v\n%s", err, raw)
		}
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("fake remote received nothing")
		return nil
	}
}

func remoteGroupFixture(t *testing.T, remoteTarget string) (*Server, *sqlite.Store) {
	t.Helper()
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.Default()
	cfg.SIP.RemoteGroups = []config.RemoteGroupConfig{{
		GroupURI:       "sip:remote_group@partner.example",
		ControllingPSI: "sip:mcptt-ctrl@partner.example",
		Target:         remoteTarget,
		Transport:      "udp",
	}}
	s := NewServer(cfg, st)
	s.timerT1Override = 20 * time.Millisecond

	// The caller must still pass the local participating checks.
	if _, err := st.CreateUser(context.Background(), store.User{
		IMPU: "sip:caller@example.test", MCPTTID: "sip:caller@example.test", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	return s, st
}

func remoteGroupInvite(callID string) string {
	sdp := "v=0\r\n" +
		"o=ue 1 1 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=application 49172 udp MCPTT\r\n"
	return "INVITE sip:remote_group@partner.example SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:remote_group@partner.example>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:caller@198.51.100.116:5060>\r\n" +
		"Answer-Mode: Auto\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + fmt.Sprint(len(sdp)) + "\r\n\r\n" + sdp
}

// The forwarded INVITE must follow TS 24.379 clause 6.3.2.1.3 and clause
// 10.1.1.3.1.1: PSI as Request-URI, the participating function's PSI
// asserted, the ICSI in P-Asserted-Service, the calling user's MCPTT ID in
// the info body, the client's SDP passed through, and no Answer-Mode copied.
func TestRemoteGroupInviteIsForwardedPerSpec(t *testing.T) {
	remote := newFakeRemote(t)
	s, _ := remoteGroupFixture(t, remote.addr())

	responses := make(chan string, 8)
	go s.handleRaw(context.Background(), "192.0.2.52:5060", "udp",
		[]byte(remoteGroupInvite("relay-fwd-1")), func(b []byte) error {
			responses <- string(b)
			return nil
		})

	fwd := remote.receive(t)
	if fwd.Method != "INVITE" || fwd.URI != "sip:mcptt-ctrl@partner.example" {
		t.Fatalf("forwarded start line: %s", fwd.StartLine)
	}
	if got := fwd.Header("P-Asserted-Service"); got != "urn:urn-7:3gpp-service.ims.icsi.mcptt" {
		t.Fatalf("P-Asserted-Service = %q", got)
	}
	if !strings.Contains(fwd.Header("P-Asserted-Identity"), "sip:mcptt-as@") {
		t.Fatalf("P-Asserted-Identity = %q, want the participating PSI", fwd.Header("P-Asserted-Identity"))
	}
	if fwd.Header("Answer-Mode") != "" {
		t.Fatalf("Answer-Mode was copied to the controlling leg: %q", fwd.Header("Answer-Mode"))
	}
	raw := string(fwd.Raw)
	for _, want := range []string{
		"<mcptt-calling-user-id><mcpttURI>sip:caller@example.test</mcpttURI></mcptt-calling-user-id>",
		"<mcptt-request-uri><mcpttURI>sip:remote_group@partner.example</mcpttURI></mcptt-request-uri>",
		"m=audio 49170 RTP/AVP 0",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("forwarded INVITE missing %q:\n%s", want, raw)
		}
	}
}

// A remote rejection is relayed to the originator with its Warning text
// intact, and the transaction layer ACKs the non-2xx final at the remote.
func TestRemoteGroupRejectionIsRelayedWithWarning(t *testing.T) {
	remote := newFakeRemote(t)
	s, _ := remoteGroupFixture(t, remote.addr())

	responses := make(chan string, 8)
	go s.handleRaw(context.Background(), "192.0.2.52:5060", "udp",
		[]byte(remoteGroupInvite("relay-rej-1")), func(b []byte) error {
			responses <- string(b)
			return nil
		})

	fwd := remote.receive(t)
	branch := viaParam(fwd.Header("Via"), "branch")

	reject := "SIP/2.0 403 Forbidden\r\n" +
		"Via: " + fwd.Header("Via") + "\r\n" +
		"From: " + fwd.Header("From") + "\r\n" +
		"To: " + fwd.Header("To") + ";tag=remotetag\r\n" +
		"Call-ID: " + fwd.Header("Call-ID") + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Warning: 399 partner.example \"119 user is not authorised to initiate the group call\"\r\n" +
		"Content-Length: 0\r\n\r\n"
	s.handleRaw(context.Background(), remote.addr(), "udp", []byte(reject), func([]byte) error { return nil })

	deadline := time.After(5 * time.Second)
	for {
		select {
		case resp := <-responses:
			if strings.HasPrefix(resp, "SIP/2.0 100") {
				continue
			}
			if !strings.HasPrefix(resp, "SIP/2.0 403") {
				t.Fatalf("originator got %q, want the relayed 403", firstLine(resp))
			}
			if !strings.Contains(resp, `"119 user is not authorised to initiate the group call"`) {
				t.Fatalf("relayed 403 lost the remote Warning text:\n%s", resp)
			}
			// The transaction layer must have ACKed the 486/403 at the remote.
			ack := remote.receive(t)
			if ack.Method != "ACK" {
				t.Fatalf("remote received %s, want the transaction-layer ACK", ack.Method)
			}
			if got := viaParam(ack.Header("Via"), "branch"); got != branch {
				t.Fatalf("ACK branch %q differs from INVITE branch %q", got, branch)
			}
			return
		case <-deadline:
			t.Fatal("originator never received the relayed verdict")
		}
	}
}

// A remote 200 is relayed with the remote SDP answer and a locally mapped
// session identity, and the remote receives the UAC-core ACK.
func TestRemoteGroupAcceptanceIsRelayed(t *testing.T) {
	remote := newFakeRemote(t)
	s, _ := remoteGroupFixture(t, remote.addr())

	responses := make(chan string, 8)
	go s.handleRaw(context.Background(), "192.0.2.52:5060", "udp",
		[]byte(remoteGroupInvite("relay-ok-1")), func(b []byte) error {
			responses <- string(b)
			return nil
		})

	fwd := remote.receive(t)
	remoteSDP := "v=0\r\no=ctrl 1 1 IN IP4 203.0.113.7\r\ns=MCPTT\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\nm=audio 41000 RTP/AVP 0\r\n"
	ok := "SIP/2.0 200 OK\r\n" +
		"Via: " + fwd.Header("Via") + "\r\n" +
		"From: " + fwd.Header("From") + "\r\n" +
		"To: " + fwd.Header("To") + ";tag=remotetag\r\n" +
		"Call-ID: " + fwd.Header("Call-ID") + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:mcptt-session-remote1@203.0.113.7>;isfocus\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + fmt.Sprint(len(remoteSDP)) + "\r\n\r\n" + remoteSDP
	s.handleRaw(context.Background(), remote.addr(), "udp", []byte(ok), func([]byte) error { return nil })

	deadline := time.After(5 * time.Second)
	for {
		select {
		case resp := <-responses:
			if strings.HasPrefix(resp, "SIP/2.0 100") {
				continue
			}
			if !strings.HasPrefix(resp, "SIP/2.0 200") {
				t.Fatalf("originator got %q, want the relayed 200", firstLine(resp))
			}
			// Clause 6.3.2.1.5.2: mapped session identity with the feature
			// tags and isfocus; the remote's SDP answer passed through.
			if !strings.Contains(resp, "Contact: <sip:mcptt-session-") || !strings.Contains(resp, ";isfocus") {
				t.Fatalf("relayed 200 lacks the mapped session identity:\n%s", resp)
			}
			if strings.Contains(resp, "mcptt-session-remote1") {
				t.Fatalf("relayed 200 leaked the remote session identity instead of mapping it:\n%s", resp)
			}
			if !strings.Contains(resp, "c=IN IP4 203.0.113.7") {
				t.Fatalf("relayed 200 lost the remote SDP answer:\n%s", resp)
			}
			if !strings.Contains(resp, "Require: timer") {
				t.Fatalf("relayed 200 lacks Require: timer:\n%s", resp)
			}
			// The remote must receive the UAC-core ACK for its 200.
			ack := remote.receive(t)
			if ack.Method != "ACK" {
				t.Fatalf("remote received %s, want the dialog ACK", ack.Method)
			}
			if ack.URI != "sip:mcptt-session-remote1@203.0.113.7" {
				t.Fatalf("ACK Request-URI = %q, want the remote Contact", ack.URI)
			}
			return
		case <-deadline:
			t.Fatal("originator never received the relayed 200")
		}
	}
}

// A remote group whose homing entry has no resolvable target is a
// configuration failure the participating function reports as 404 with
// warning "142" (clause 10.1.1.3.1.1).
func TestRemoteGroupWithoutTargetGets404With142(t *testing.T) {
	s, _ := remoteGroupFixture(t, "")
	// PSI without a host:port that addrFromSIPURI can resolve to a target
	// still yields a target; force the unresolvable case explicitly.
	s.cfg.SIP.RemoteGroups[0].Target = ""
	s.cfg.SIP.RemoteGroups[0].ControllingPSI = ""

	var got []string
	s.handleRaw(context.Background(), "192.0.2.52:5060", "udp",
		[]byte(remoteGroupInvite("relay-notgt-1")), func(b []byte) error {
			got = append(got, string(b))
			return nil
		})

	last := got[len(got)-1]
	if !strings.HasPrefix(last, "SIP/2.0 404") {
		t.Fatalf("got %q, want 404", firstLine(last))
	}
	if !strings.Contains(last, `"142 unable to determine the controlling function"`) {
		t.Fatalf("404 lacks warning 142:\n%s", last)
	}
}

// A CANCEL while the relayed INVITE rings is forwarded to the remote
// controlling function with the INVITE's branch and dialog identifiers
// (RFC 3261 clause 9.1), and the caller gets its 487.
func TestCancelRelayedToRemoteControlling(t *testing.T) {
	remote := newFakeRemote(t)
	s, _ := remoteGroupFixture(t, remote.addr())

	inviteRaw := remoteGroupInvite("rc-cancel-1")
	go func() {
		s.handleRaw(context.Background(), "192.0.2.52:5060", "udp", []byte(inviteRaw), func(b []byte) error {
			return nil
		})
	}()

	// The relayed INVITE reaches the remote; it rings without answering.
	relayed := remote.receive(t)
	if !strings.HasPrefix(relayed.StartLine, "INVITE ") {
		t.Fatalf("expected relayed INVITE, got %q", relayed.StartLine)
	}

	cancel := "CANCEL sip:remote_group@partner.example SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKrc-cancel-1\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:remote_group@partner.example>\r\n" +
		"Call-ID: rc-cancel-1\r\n" +
		"CSeq: 1 CANCEL\r\n" +
		"Content-Length: 0\r\n\r\n"
	var cancelResp []string
	s.handleRaw(context.Background(), "192.0.2.52:5060", "udp", []byte(cancel), func(b []byte) error {
		cancelResp = append(cancelResp, string(b))
		return nil
	})
	if len(cancelResp) == 0 || !strings.HasPrefix(cancelResp[0], "SIP/2.0 200") {
		t.Fatalf("CANCEL responses = %v, want 200 first", cancelResp)
	}

	// The CANCEL is forwarded mirroring the INVITE's identifiers, filtered
	// out from the INVITE retransmissions the unanswered relay produces.
	deadline := time.After(3 * time.Second)
	var forwarded *Message
	for forwarded == nil {
		select {
		case raw := <-remote.got:
			m, err := Parse(raw)
			if err == nil && strings.HasPrefix(m.StartLine, "CANCEL ") {
				forwarded = m
			}
		case <-deadline:
			t.Fatal("remote never received the CANCEL")
		}
	}
	if relayed.Header("Via") != forwarded.Header("Via") {
		t.Fatalf("CANCEL Via %q does not mirror the INVITE Via %q",
			forwarded.Header("Via"), relayed.Header("Via"))
	}
	if relayed.Header("Call-ID") != forwarded.Header("Call-ID") {
		t.Fatal("CANCEL Call-ID does not match the relayed INVITE")
	}
}

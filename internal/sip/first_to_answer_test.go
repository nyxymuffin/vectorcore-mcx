package sip

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

// ftaInvite builds a clause 11.1.1.2.1 first-to-answer INVITE with several
// candidates in the resource-lists body.
func ftaInvite(callID string, candidates []string) string {
	info := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		`<session-type>first-to-answer</session-type>` +
		`</mcptt-Params></mcpttinfo>`
	lists := `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>`
	for _, c := range candidates {
		lists += `<entry uri="` + c + `"/>`
	}
	lists += `</list></resource-lists>`
	sdp := "v=0\r\n" +
		"o=ue 1 1 IN IP4 198.51.100.116\r\n" +
		"s=MCPTT\r\n" +
		"c=IN IP4 198.51.100.116\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=application 49172 udp MCPTT\r\n" +
		"a=fmtp:MCPTT mc_implicit_request\r\n"
	body := "--fta\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + info +
		"\r\n--fta\r\nContent-Type: application/resource-lists+xml\r\n\r\n" + lists +
		"\r\n--fta\r\nContent-Type: application/sdp\r\n\r\n" + sdp +
		"\r\n--fta--\r\n"
	return "INVITE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:caller@example.test>;tag=from1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:caller@198.51.100.116:5060>\r\n" +
		`Content-Type: multipart/mixed;boundary="fta"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

// ftaCandidateSocket provisions a served, registered candidate on a live
// socket and returns a helper that reads its INVITE and optionally answers.
type ftaSocket struct {
	sock net.PacketConn
	port string
	mu   sync.Mutex
	msgs []string
}

func (f *ftaSocket) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

func newFTACandidate(t *testing.T, s *Server, st *sqlite.Store, impu string, answer bool) *ftaSocket {
	t.Helper()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, store.User{IMPU: impu, MCPTTID: impu, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	_, portStr, _ := net.SplitHostPort(sock.LocalAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: impu, Registered: true,
		ContactURI: "sip:" + impu + "@127.0.0.1:" + portStr,
		SourceIP:   "127.0.0.1", SourcePort: port, Transport: "udp",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fs := &ftaSocket{sock: sock, port: portStr}
	go func() {
		buf := make([]byte, 8192)
		for {
			_ = sock.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, _, err := sock.ReadFrom(buf)
			if err != nil {
				return
			}
			raw := string(buf[:n])
			fs.mu.Lock()
			fs.msgs = append(fs.msgs, raw)
			fs.mu.Unlock()
			if answer && strings.HasPrefix(raw, "INVITE ") {
				via := headerLine(raw, "Via")
				fromH := headerLine(raw, "From")
				toH := headerLine(raw, "To") + ";tag=fta-" + portStr
				callIDH := headerLine(raw, "Call-ID")
				cseq := headerLine(raw, "CSeq")
				sdp := "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
					"m=audio 40020 RTP/AVP 0\r\n"
				resp := "SIP/2.0 200 OK\r\n" +
					"Via: " + via + "\r\n" +
					"From: " + fromH + "\r\n" +
					"To: " + toH + "\r\n" +
					"Call-ID: " + callIDH + "\r\n" +
					"CSeq: " + cseq + "\r\n" +
					"Contact: <sip:" + impu + "@127.0.0.1:" + portStr + ">\r\n" +
					"Content-Type: application/sdp\r\n" +
					"Content-Length: " + fmt.Sprint(len(sdp)) + "\r\n\r\n" + sdp
				s.handleRaw(context.Background(), "127.0.0.1:"+portStr, "udp", []byte(resp), func([]byte) error { return nil })
			}
		}
	}()
	return fs
}

// The first candidate to answer wins: the caller's 200 names the winner in
// mcptt-called-party-id, every candidate leg carried Priv-Answer-Mode:
// Manual, and the silent candidate is not the winner.
func TestFirstToAnswerWinnerNamedInCalledPartyID(t *testing.T) {
	s, st := privateFixture(t)

	answering := newFTACandidate(t, s, st, "sip:quick@example.test", true)
	silent := newFTACandidate(t, s, st, "sip:slow@example.test", false)

	responses := collectResponses(t, s,
		ftaInvite("fta-1", []string{"sip:quick@example.test", "sip:slow@example.test"}))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}
	final := responses[2]
	if !strings.Contains(final, "<mcptt-called-party-id><mcpttURI>sip:quick@example.test</mcpttURI></mcptt-called-party-id>") {
		t.Fatalf("200 does not name the winner:\n%s", final)
	}

	// Both candidates were invited with Priv-Answer-Mode: Manual (clause
	// 11.1.1.4.1 step 3) and without Answer-Mode.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(answering.messages()) > 0 && len(silent.messages()) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("candidates not both invited: quick=%d slow=%d", len(answering.messages()), len(silent.messages()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, fs := range []*ftaSocket{answering, silent} {
		invite := fs.messages()[0]
		if !strings.Contains(invite, "Priv-Answer-Mode: Manual\r\n") {
			t.Fatalf("candidate INVITE lacks Priv-Answer-Mode: Manual:\n%s", invite)
		}
		if strings.Contains(invite, "\r\nAnswer-Mode:") {
			t.Fatalf("first-to-answer leg must not carry Answer-Mode:\n%s", invite)
		}
		if !strings.Contains(invite, "<session-type>first-to-answer</session-type>") {
			t.Fatalf("candidate INVITE lacks the session type:\n%s", invite)
		}
	}
}

// A losing candidate that answers after the winner is released with a BYE
// carrying release-reason "not selected for call" (clause 11.1.1.4.2 step 8).
func TestFirstToAnswerLoserGetsNotSelectedBYE(t *testing.T) {
	s, st := privateFixture(t)

	quick := newFTACandidate(t, s, st, "sip:quick@example.test", true)
	_ = quick
	late := newFTACandidateDelayed(t, s, st, "sip:late@example.test", 300*time.Millisecond)

	responses := collectResponses(t, s,
		ftaInvite("fta-2", []string{"sip:quick@example.test", "sip:late@example.test"}))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}
	if !strings.Contains(responses[2], "sip:quick@example.test") {
		t.Fatalf("winner should be the quick candidate:\n%s", responses[2])
	}

	// The late answerer must receive a BYE with the release reason.
	deadline := time.Now().Add(3 * time.Second)
	for {
		var bye string
		for _, m := range late.messages() {
			if strings.HasPrefix(m, "BYE ") {
				bye = m
			}
		}
		if bye != "" {
			if !strings.Contains(bye, "<release-reason>not selected for call</release-reason>") {
				t.Fatalf("loser BYE lacks the release reason:\n%s", bye)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("late loser never received a BYE; messages:\n%s", strings.Join(late.messages(), "\n---\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// newFTACandidateDelayed answers its INVITE after a delay.
func newFTACandidateDelayed(t *testing.T, s *Server, st *sqlite.Store, impu string, delay time.Duration) *ftaSocket {
	t.Helper()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, store.User{IMPU: impu, MCPTTID: impu, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	_, portStr, _ := net.SplitHostPort(sock.LocalAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if _, err := st.UpsertRegistration(ctx, store.Registration{
		PublicIdentity: impu, Registered: true,
		ContactURI: "sip:" + impu + "@127.0.0.1:" + portStr,
		SourceIP:   "127.0.0.1", SourcePort: port, Transport: "udp",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fs := &ftaSocket{sock: sock, port: portStr}
	go func() {
		buf := make([]byte, 8192)
		for {
			_ = sock.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, _, err := sock.ReadFrom(buf)
			if err != nil {
				return
			}
			raw := string(buf[:n])
			fs.mu.Lock()
			fs.msgs = append(fs.msgs, raw)
			fs.mu.Unlock()
			if strings.HasPrefix(raw, "INVITE ") {
				go func(invite string) {
					time.Sleep(delay)
					via := headerLine(invite, "Via")
					fromH := headerLine(invite, "From")
					toH := headerLine(invite, "To") + ";tag=fta-late-" + portStr
					callIDH := headerLine(invite, "Call-ID")
					cseq := headerLine(invite, "CSeq")
					sdp := "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
						"m=audio 40021 RTP/AVP 0\r\n"
					resp := "SIP/2.0 200 OK\r\n" +
						"Via: " + via + "\r\n" +
						"From: " + fromH + "\r\n" +
						"To: " + toH + "\r\n" +
						"Call-ID: " + callIDH + "\r\n" +
						"CSeq: " + cseq + "\r\n" +
						"Contact: <sip:" + impu + "@127.0.0.1:" + portStr + ">\r\n" +
						"Content-Type: application/sdp\r\n" +
						"Content-Length: " + fmt.Sprint(len(sdp)) + "\r\n\r\n" + sdp
					s.handleRaw(context.Background(), "127.0.0.1:"+portStr, "udp", []byte(resp), func([]byte) error { return nil })
				}(raw)
			}
		}
	}()
	return fs
}

// Without a resource-lists body the called parties cannot be determined.
func TestFirstToAnswerWithoutCandidatesGets403With145(t *testing.T) {
	s, _ := privateFixture(t)
	responses := collectResponses(t, s, ftaInvite("fta-145", nil))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 403") {
		t.Fatalf("responses = %v, want exactly one 403", responses)
	}
	if !strings.Contains(responses[0], `"145 unable to determine called party"`) {
		t.Fatalf("403 lacks warning 145:\n%s", responses[0])
	}
}

// A still-ringing loser is CANCELled rather than left to time out
// (clause 11.1.1.4.2 step 8 b).
func TestFirstToAnswerCancelsRingingLoser(t *testing.T) {
	s, st := privateFixture(t)

	quick := newFTACandidate(t, s, st, "sip:quick@example.test", true)
	_ = quick
	// This candidate never answers: it must receive a CANCEL.
	silent := newFTACandidate(t, s, st, "sip:silent@example.test", false)

	responses := collectResponses(t, s,
		ftaInvite("fta-cancel", []string{"sip:quick@example.test", "sip:silent@example.test"}))
	if len(responses) != 3 || !strings.HasPrefix(responses[2], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 100/180/200", responses)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		var cancel string
		for _, m := range silent.messages() {
			if strings.HasPrefix(m, "CANCEL ") {
				cancel = m
			}
		}
		if cancel != "" {
			// RFC 3261 clause 9.1: the CANCEL mirrors the INVITE's branch.
			var invite string
			for _, m := range silent.messages() {
				if strings.HasPrefix(m, "INVITE ") {
					invite = m
				}
			}
			if headerLine(invite, "Via") != headerLine(cancel, "Via") {
				t.Fatalf("CANCEL Via %q does not mirror the INVITE Via %q",
					headerLine(cancel, "Via"), headerLine(invite, "Via"))
			}
			if headerLine(invite, "Call-ID") != headerLine(cancel, "Call-ID") {
				t.Fatal("CANCEL Call-ID does not match the leg")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ringing loser never cancelled; messages:\n%s",
				strings.Join(silent.messages(), "\n---\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

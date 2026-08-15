package sip

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

func locationMessage(callID, from, targetURI, locBody string) string {
	info := ""
	if targetURI != "" {
		info = `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
			`<mcptt-request-uri><mcpttURI>` + targetURI + `</mcpttURI></mcptt-request-uri>` +
			`</mcptt-Params></mcpttinfo>`
	}
	body := ""
	if info != "" {
		body = "--loc\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + info +
			"\r\n--loc\r\nContent-Type: application/vnd.3gpp.mcptt-location-info+xml\r\n\r\n" + locBody +
			"\r\n--loc--\r\n"
		return "MESSAGE sip:mcptt-as@example.test SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
			"From: <" + from + ">;tag=l1\r\n" +
			"To: <sip:mcptt-as@example.test>\r\n" +
			"Call-ID: " + callID + "\r\n" +
			"CSeq: 1 MESSAGE\r\n" +
			`Content-Type: multipart/mixed;boundary="loc"` + "\r\n" +
			"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
	}
	return "MESSAGE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bK" + callID + "\r\n" +
		"From: <" + from + ">;tag=l1\r\n" +
		"To: <sip:mcptt-as@example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		"Content-Type: application/vnd.3gpp.mcptt-location-info+xml\r\n" +
		"Content-Length: " + fmt.Sprint(len(locBody)) + "\r\n\r\n" + locBody
}

const sampleReport = `<location-info xmlns="urn:3gpp:ns:mcpttLocationInfo:1.0"><Report ReportType="NonEmergency"><TriggerId>vectorcore-periodic</TriggerId><CurrentLocation><PointCoordinate><longitude>-121.5</longitude><latitude>38.5</latitude></PointCoordinate></CurrentLocation></Report></location-info>`

// A location report from a served user is stored (clause 13.2.4.1).
func TestLocationReportStored(t *testing.T) {
	s, st := groupCallFixture(t)
	responses := collectResponses(t, s, locationMessage("loc-1", "sip:caller@example.test", "", sampleReport))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want 200", responses)
	}
	state, err := st.GetPublishedState(context.Background(), "sip:caller@example.test", "location")
	if err != nil || state == nil {
		t.Fatalf("location not stored: %v", err)
	}
	if !strings.Contains(state.Body, "<longitude>-121.5</longitude>") {
		t.Fatalf("stored body:\n%s", state.Body)
	}
}

// An on-demand request relays a clause 13.2.3.1 <Request> to the target, and
// the target's subsequent report is forwarded to the requester.
func TestLocationRequestRelayAndReportForward(t *testing.T) {
	s, st := groupCallFixture(t)
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, store.User{IMPU: "sip:target@example.test", MCPTTID: "sip:target@example.test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	targetSock := registerAtSocket(t, st, "sip:target@example.test")
	requesterSock := registerAtSocket(t, st, "sip:caller@example.test")

	req := `<location-info xmlns="urn:3gpp:ns:mcpttLocationInfo:1.0"><Request/></location-info>`
	responses := collectResponses(t, s, locationMessage("loc-2", "sip:caller@example.test", "sip:target@example.test", req))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("request responses = %v, want 200", responses)
	}

	buf := make([]byte, 8192)
	_ = targetSock.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := targetSock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("target never received the location request: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "<Request/>") {
		t.Fatalf("relayed request lacks <Request/>:\n%s", buf[:n])
	}

	// The target reports; the requester gets the forwarded report.
	responses = collectResponses(t, s, locationMessage("loc-3", "sip:target@example.test", "", sampleReport))
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("report responses = %v, want 200", responses)
	}
	_ = requesterSock.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = requesterSock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("requester never received the forwarded report: %v", err)
	}
	fwd := string(buf[:n])
	if !strings.Contains(fwd, "<longitude>-121.5</longitude>") ||
		!strings.Contains(fwd, "<mcptt-calling-user-id><mcpttURI>sip:target@example.test</mcpttURI></mcptt-calling-user-id>") {
		t.Fatalf("forwarded report incomplete:\n%s", fwd)
	}
}

// With a configured interval, registration triggers the clause 13.2.2
// configuration push with a PeriodicReport trigger.
func TestLocationConfigurationPushedOnRegister(t *testing.T) {
	s, st := groupCallFixture(t)
	s.cfg.SIP.Location.ReportIntervalSeconds = 60

	var mu sync.Mutex
	var sent []string
	s.clientTxSendOverride = func(transport, target string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, string(packet))
		return nil
	}
	_ = registerAtSocket(t, st, "sip:caller@example.test")

	register := "REGISTER sip:example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.52:5060;branch=z9hG4bKlocreg\r\n" +
		"From: <sip:caller@example.test>;tag=r1\r\n" +
		"To: <sip:caller@example.test>\r\n" +
		"Call-ID: loc-reg-1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:caller@192.0.2.52:5060>;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\"\r\n" +
		"Expires: 3600\r\n" +
		"Content-Length: 0\r\n\r\n"
	responses := collectResponses(t, s, register)
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("register responses = %v, want 200", responses)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		var cfgMsg string
		for _, m := range sent {
			if strings.HasPrefix(m, "MESSAGE ") && strings.Contains(m, "<Configuration>") {
				cfgMsg = m
			}
		}
		mu.Unlock()
		if cfgMsg != "" {
			if !strings.Contains(cfgMsg, `<PeriodicReport TriggerId="vectorcore-periodic">60</PeriodicReport>`) {
				t.Fatalf("configuration lacks the periodic trigger:\n%s", cfgMsg)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no location configuration MESSAGE sent after registration")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

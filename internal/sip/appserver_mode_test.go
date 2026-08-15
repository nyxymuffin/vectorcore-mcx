package sip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

// Third-party REGISTER as the S-CSCF sends it over ISC: the client's original
// REGISTER travels in the message/sip body (TS 24.379 clause 7.3.2).
func thirdPartyRegister(token string) string {
	innerInfo := `<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>` +
		`<mcptt-access-token type="Normal"><mcpttString>` + token + `</mcpttString></mcptt-access-token>` +
		`<mcptt-client-id type="Normal"><mcpttString>client-1</mcpttString></mcptt-client-id>` +
		`</mcptt-Params></mcpttinfo>`
	inner := "REGISTER sip:ims.example.test SIP/2.0\r\n" +
		"From: <sip:ue@ims.example.test>;tag=u1\r\n" +
		"To: <sip:ue@ims.example.test>\r\n" +
		"Call-ID: inner-1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:ue@198.51.100.116:5060>;+g.3gpp.mcptt\r\n" +
		"Content-Type: application/vnd.3gpp.mcptt-info+xml\r\n" +
		"Content-Length: " + fmt.Sprint(len(innerInfo)) + "\r\n\r\n" + innerInfo

	body := "--tp\r\nContent-Type: message/sip\r\n\r\n" + inner + "\r\n--tp--\r\n"
	return "REGISTER sip:mcptt-as.ims.example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.50:5060;branch=z9hG4bKtp1\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:scscf.ims.example.test>;tag=scscf\r\n" +
		"To: <sip:ue@ims.example.test>\r\n" +
		"Call-ID: tp-reg-1\r\n" +
		"CSeq: 10 REGISTER\r\n" +
		"Contact: <sip:ue@198.51.100.116:5060>;+g.3gpp.mcptt\r\n" +
		"Expires: 3600\r\n" +
		"Event: registration\r\n" +
		`Content-Type: multipart/mixed;boundary="tp"` + "\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

func appServerFixture(t *testing.T) (*Server, *sqlite.Store, *ecdsa.PrivateKey, string) {
	t.Helper()
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "reg-key"
	jwks := writeJWKS(t, t.TempDir(), kid, &key.PublicKey)

	cfg := config.Default()
	cfg.SIP.Mode = "application_server"
	cfg.SIP.Auth.TrustedJWKSFile = jwks
	// The validator is built when either consumer needs it; reuse the
	// service-authorization plumbing.
	cfg.SIP.Auth.RequireServiceAuthorization = true
	return NewServer(cfg, st), st, key, kid
}

// In application_server mode a third-party REGISTER binds the MCPTT ID from
// the validated access token to the IMS public user identity (clause 7.3.2
// steps 2-4).
func TestApplicationServerModeBindsMCPTTIDFromToken(t *testing.T) {
	s, st, key, kid := appServerFixture(t)
	token := signES256(t, key, kid, validClaims("sip:mcptt-bound@example.test"))

	var responses []string
	s.handleRaw(context.Background(), "192.0.2.50:5060", "udp",
		[]byte(thirdPartyRegister(token)), func(b []byte) error {
			responses = append(responses, string(b))
			return nil
		})
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want one 200", responses)
	}

	regs, err := st.ListRegistrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 {
		t.Fatalf("registrations = %d, want 1", len(regs))
	}
	if regs[0].MCPTTID != "sip:mcptt-bound@example.test" {
		t.Fatalf("bound MCPTT ID = %q, want the token identity", regs[0].MCPTTID)
	}
	if regs[0].PublicIdentity != "sip:ue@ims.example.test" {
		t.Fatalf("public identity = %q", regs[0].PublicIdentity)
	}
}

// An invalid token must not bind an identity, but the REGISTER itself still
// succeeds: 7.3.2 specifies binding on success, not rejection of the
// registration.
func TestApplicationServerModeDoesNotBindOnBadToken(t *testing.T) {
	s, st, _, _ := appServerFixture(t)
	rogue, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := signES256(t, rogue, "rogue", validClaims("sip:forged@example.test"))

	var responses []string
	s.handleRaw(context.Background(), "192.0.2.50:5060", "udp",
		[]byte(thirdPartyRegister(token)), func(b []byte) error {
			responses = append(responses, string(b))
			return nil
		})
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want one 200", responses)
	}

	regs, err := st.ListRegistrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 || regs[0].MCPTTID != "" {
		t.Fatalf("a forged token must not bind an identity: %+v", regs)
	}
}

// Standalone mode must ignore the message/sip body entirely: no binding.
func TestStandaloneModeIgnoresThirdPartyBody(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := NewServer(config.Default(), st) // mode defaults to standalone

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := signES256(t, key, "k", validClaims("sip:should-not-bind@example.test"))

	var responses []string
	s.handleRaw(context.Background(), "192.0.2.50:5060", "udp",
		[]byte(thirdPartyRegister(token)), func(b []byte) error {
			responses = append(responses, string(b))
			return nil
		})
	if len(responses) != 1 || !strings.HasPrefix(responses[0], "SIP/2.0 200") {
		t.Fatalf("responses = %v, want one 200", responses)
	}

	regs, err := st.ListRegistrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 || regs[0].MCPTTID != "" {
		t.Fatalf("standalone mode must not bind from the third-party body: %+v", regs)
	}
}

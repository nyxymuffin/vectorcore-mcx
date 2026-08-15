package sip

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// A MIME part body is opaque octets. TS 33.180 clause 9.2.1.3 carries a
// binary MIKEY-SAKKE I_MESSAGE in an application/mikey part, and the
// signature of clause E.1.2 covers the whole message, so losing a single
// octet in transit makes the upload fail verification.
//
// The part parser used to trim whitespace from each section, which ate
// the final octet of any body ending in one of the six bytes Go counts
// as space. That is one message in roughly forty - frequent enough to
// break uploads in service, rare enough that a single run of a test
// would usually pass.
func TestMultipartPreservesBinaryBodies(t *testing.T) {
	const iterations = 5000
	for i := 0; i < iterations; i++ {
		payload := make([]byte, 400)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		// Force the interesting case often rather than waiting for it.
		if i%4 == 0 {
			payload[len(payload)-1] = []byte{' ', '\r', '\n', '\t'}[i%4]
		}

		msg, err := Parse([]byte(
			"REGISTER sip:mcptt-server@example.test SIP/2.0\r\n" +
				"Via: SIP/2.0/UDP client.example.test;branch=z9hG4bK-bin\r\n" +
				"From: <sip:a@example.test>;tag=1\r\nTo: <sip:a@example.test>\r\n" +
				"Call-ID: binary\r\nCSeq: 1 REGISTER\r\n" +
				"Content-Type: multipart/mixed;boundary=\"b1\"\r\n\r\n" +
				"--b1\r\nContent-Type: application/mikey\r\n\r\n" +
				string(payload) + "\r\n--b1--\r\n"))
		if err != nil {
			t.Fatalf("iteration %d: parse: %v", i, err)
		}
		part := msg.Part("application/mikey")
		if part == nil {
			t.Fatalf("iteration %d: the part went missing", i)
		}
		if !bytes.Equal(part.Body, payload) {
			t.Fatalf("iteration %d: body is %d octets, want %d (last octet of the original was %#x)",
				i, len(part.Body), len(payload), payload[len(payload)-1])
		}
	}
}

// The surrounding parts still work: a body ending in whitespace must not
// disturb the part beside it, and the close delimiter is still skipped.
func TestMultipartWithBinaryAndTextParts(t *testing.T) {
	binary := []byte{0x01, 0x02, 0x03, '\r', '\n'}
	msg, err := Parse([]byte(
		"REGISTER sip:mcptt-server@example.test SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP client.example.test;branch=z9hG4bK-mix\r\n" +
			"From: <sip:a@example.test>;tag=1\r\nTo: <sip:a@example.test>\r\n" +
			"Call-ID: mixed\r\nCSeq: 1 REGISTER\r\n" +
			"Content-Type: multipart/mixed;boundary=\"b1\"\r\n\r\n" +
			"--b1\r\nContent-Type: application/mikey\r\n\r\n" + string(binary) + "\r\n" +
			"--b1\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" +
			"<mcpttinfo/>\r\n--b1--\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Parts()) != 2 {
		t.Fatalf("got %d parts, want 2", len(msg.Parts()))
	}
	if got := msg.Part("application/mikey"); got == nil || !bytes.Equal(got.Body, binary) {
		t.Fatalf("binary part = %#v", got)
	}
	if got := msg.Part("application/vnd.3gpp.mcptt-info+xml"); got == nil ||
		string(got.Body) != "<mcpttinfo/>" {
		t.Fatalf("xml part = %#v", got)
	}
}

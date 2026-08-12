package sip

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
)

func readerFor(s string) *bufio.Reader {
	return bufio.NewReaderSize(strings.NewReader(s), sipReaderBufferBytes)
}

// A well-formed message must still be accepted unchanged.
func TestReadSIPMessageAcceptsNormalMessage(t *testing.T) {
	body := "v=0\r\n"
	raw := "OPTIONS sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Call-ID: ok-1\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body

	got, err := readSIPMessage(readerFor(raw))
	if err != nil {
		t.Fatalf("well-formed message rejected: %v", err)
	}
	if string(got) != raw {
		t.Fatalf("message = %q, want %q", got, raw)
	}
}

// A single header line longer than the reader buffer must fail as a bounded
// error. bufio.Reader.ReadString would instead grow until memory ran out.
func TestReadSIPMessageRejectsOverlongHeaderLine(t *testing.T) {
	raw := "OPTIONS sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Subject: " + strings.Repeat("A", sipReaderBufferBytes+1) + "\r\n\r\n"

	_, err := readSIPMessage(readerFor(raw))
	if err == nil {
		t.Fatal("expected an overlong header line to be rejected")
	}
	if !strings.Contains(err.Error(), "header line exceeds") {
		t.Fatalf("error %q does not identify the overlong line", err)
	}
}

// Many short header lines with no terminating blank line must also be bounded.
func TestReadSIPMessageRejectsOversizeHeaderSection(t *testing.T) {
	var b strings.Builder
	b.WriteString("OPTIONS sip:mcptt-as@example.test SIP/2.0\r\n")
	for b.Len() <= maxSIPHeaderBytes {
		b.WriteString("X-Filler: padding\r\n")
	}

	_, err := readSIPMessage(readerFor(b.String()))
	if err == nil {
		t.Fatal("expected an oversize header section to be rejected")
	}
	if !strings.Contains(err.Error(), "header section exceeds") {
		t.Fatalf("error %q does not identify the oversize header section", err)
	}
}

// Content-Length is attacker controlled and must be range-checked before it is
// used to size an allocation. The body is deliberately absent: reaching the
// limit error rather than an unexpected EOF proves the check runs first.
func TestReadSIPMessageRejectsOversizeContentLengthBeforeAllocating(t *testing.T) {
	raw := "INVITE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Call-ID: huge-1\r\n" +
		"Content-Length: 2000000000\r\n\r\n"

	_, err := readSIPMessage(readerFor(raw))
	if err == nil {
		t.Fatal("expected an oversize Content-Length to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf("error %q does not identify the oversize body; a short read would mean the cap ran after the allocation", err)
	}
}

func TestReadSIPMessageRejectsNegativeContentLength(t *testing.T) {
	raw := "INVITE sip:mcptt-as@example.test SIP/2.0\r\n" +
		"Call-ID: neg-1\r\n" +
		"Content-Length: -1\r\n\r\n"

	if _, err := readSIPMessage(readerFor(raw)); err == nil {
		t.Fatal("expected a negative Content-Length to be rejected")
	}
}

// A connection that is opened and then left silent must be reclaimed rather
// than holding a goroutine and socket indefinitely.
func TestHandleTCPConnClosesSilentConnection(t *testing.T) {
	restore := sipTCPReadTimeout
	sipTCPReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { sipTCPReadTimeout = restore })

	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	s := NewServer(config.Default(), nil)
	done := make(chan struct{})
	go func() {
		s.handleTCPConn(context.Background(), server)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleTCPConn did not return; a silent peer holds the connection open")
	}
}

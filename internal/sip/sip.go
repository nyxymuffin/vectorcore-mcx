package sip

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/cms"
	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/tlsutil"
)

type Server struct {
	cfg                config.Config
	st                 store.Store
	learned            map[string]learnedRoute
	mu                 sync.Mutex
	pendingInvites     sync.Map // callID → chan *Message, for RX INVITE 200 OK dispatch
	ueSubRoute         sync.Map // lower(IMPU) → store.Subscription, latest subscription per UE for RX INVITE routing
	uasInvites         sync.Map // callID → *uasInviteState, UAS INVITE pending final response (for CANCEL §9.2)
	notifyCSeq         sync.Map // sub.CallID → uint32, per-dialog NOTIFY CSeq counter (RFC 3261 §20.16)
	chatSessions       sync.Map // lower(groupURI) → session identity URI of the ongoing chat session (TS 24.379 §10.1.2.4.1.1)
	xcapSubs           sync.Map // sub.CallID → store.Subscription, active xcap-diff subscriptions for change NOTIFY (RFC 5875)
	emergencyAlerts    *alertState
	confSubs           *conferenceSubs
	regroups           *regroupState
	sdsCorrelation     *sdsCorrelator
	rxLegCancel        sync.Map // leg callID → *rxCancelState, in-flight RX INVITEs that can be cancelled
	pesSessions        sync.Map // callID → *pesSession, established pre-established sessions (TS 24.379 §8)
	remoteInvites      sync.Map // original callID → *remoteInviteState, in-flight relayed INVITEs (CANCEL relay)
	locationRequests   sync.Map // lower(target IMPU) → requester IMPU, pending on-demand location fetches (TS 24.379 §13.2.3.2)
	confVersion        atomic.Int64
	inProgressPriority sync.Map // lower(groupURI) → "emergency" | "imminent" in-progress state (TS 24.379 §4.6)

	// Test hooks for RFC 4028 supervision (per-server, not global - a global
	// mutated by tests races with the servers of other tests).
	// keyMgmt is this server's own KMS-provisioned key material and
	// cskKeys the Client-Server Keys clients have uploaded to it
	// (TS 33.180 clauses 5.4 and 9.2.1).
	keyMgmt                     *keyManagement
	cskKeys                     *cskStore
	sessionExpiryOverride       time.Duration
	sessionReapIntervalOverride time.Duration
	// clientTxSendOverride, when set, replaces the outbound socket write of
	// client transactions so tests can capture generated requests.
	clientTxSendOverride func(transport, target string, packet []byte) error
	transactions         sync.Map // transactionKey → *serverTransaction, for retransmission absorption (RFC 3261 §17.2)

	// Concurrency limits for the listeners. Each is a counting semaphore: a
	// slot is taken before a handler starts and released when it returns.
	udpSem     chan struct{}
	tcpSem     chan struct{}
	authTokens *tokenValidator

	// streamReadTimeoutOverride, when non-zero, replaces defaultStreamReadTimeout.
	// Tests set it per-Server; production leaves it zero.
	streamReadTimeoutOverride time.Duration

	// clientTx holds in-flight client transactions (RFC 3261 clause 17.1),
	// keyed branch|METHOD. timerT1Override shortens T1 in tests, per-server
	// for the same reason as streamReadTimeoutOverride.
	clientTx        sync.Map
	timerT1Override time.Duration

	// sessionIdentities maps Call-ID to the allocated MCPTT session identity
	// (TS 24.379 clause 4.5) for the lifetime of the group session.
	sessionIdentities sync.Map

	// remoteSessions maps an originating leg's Call-ID to the relayed dialog
	// state toward a remote controlling function (slice 5).
	remoteSessions sync.Map
	udpDropped     atomic.Uint64
	tcpRefused     atomic.Uint64
}

// Bounds on concurrent work started by the listeners. Every handler can open a
// database transaction, so an unbounded fan-out turns a traffic burst into
// connection-pool exhaustion and memory pressure rather than backpressure.
const (
	maxConcurrentUDPHandlers = 256
	maxConcurrentTCPConns    = 256
)

type Message struct {
	StartLine string
	Method    string
	URI       string
	Version   string
	Headers   map[string][]string
	Body      []byte
	Raw       []byte
}

type Part struct {
	Headers map[string]string
	Body    []byte
}

type responder func([]byte) error

const productName = "VectorCore MCX"

type learnedRoute struct {
	Target    string
	Transport string
}

type uasInviteState struct {
	msg  *Message
	send responder
	tag  string
}

func NewServer(cfg config.Config, st store.Store) *Server {
	s := &Server{
		cfg:             cfg,
		st:              st,
		learned:         map[string]learnedRoute{},
		emergencyAlerts: newAlertState(),
		confSubs:        newConferenceSubs(),
		regroups:        newRegroupState(),
		sdsCorrelation:  newSDSCorrelator(),
		cskKeys:         newCSKStore(),
		udpSem:          make(chan struct{}, maxConcurrentUDPHandlers),
		tcpSem:          make(chan struct{}, maxConcurrentTCPConns),
	}
	s.initKeyManagement()
	if cfg.SIP.Auth.RequireServiceAuthorization {
		validator, err := newTokenValidator(cfg.SIP.Auth.TrustedJWKSFile, cfg.SIP.Auth.TrustedIssuer)
		if err != nil {
			// Fail closed: with authorization required and no working
			// validator, every service authorization is refused rather than
			// admitted.
			slog.Error("SIP service authorization enabled but token validator unavailable; all service authorization will be refused", "err", err)
		} else {
			s.authTokens = validator
		}
	}
	return s
}

func (s *Server) StartOptions(ctx context.Context) error {
	if !s.cfg.SIP.Options.Enabled {
		<-ctx.Done()
		return nil
	}
	interval, err := time.ParseDuration(s.cfg.SIP.Options.Interval)
	if err != nil || interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.sendOptions(ctx)
		}
	}
}

func (s *Server) ListenUDP(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.cfg.SIP.UDPListen)
	if err != nil {
		return err
	}
	defer pc.Close()
	slog.Info("SIP UDP listening", "addr", s.cfg.SIP.UDPListen)

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		raw := append([]byte(nil), buf[:n]...)
		if !s.servePacket(ctx, pc, addr, raw) {
			if n := s.udpDropped.Add(1); n%100 == 1 {
				slog.Warn("SIP UDP overloaded, datagram dropped",
					"source", addr.String(), "limit", cap(s.udpSem), "dropped_total", n)
			}
		}
	}
}

// servePacket starts handling a datagram if a slot is free, and reports
// whether it was accepted.
//
// Load is shed rather than queued: SIP peers retransmit, so dropping a
// datagram under overload recovers, whereas spawning goroutines without limit
// does not.
func (s *Server) servePacket(ctx context.Context, pc net.PacketConn, addr net.Addr, raw []byte) bool {
	select {
	case s.udpSem <- struct{}{}:
		go func() {
			defer func() { <-s.udpSem }()
			s.handlePacket(ctx, pc, addr, raw, "udp")
		}()
		return true
	default:
		return false
	}
}

func (s *Server) ListenTCP(ctx context.Context) error {
	if strings.TrimSpace(s.cfg.SIP.TCPListen) == "" {
		// Disabled. Block rather than return: main treats the first value on
		// its error channel as the signal to shut down, so an immediate nil
		// would stop the whole process.
		<-ctx.Done()
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.SIP.TCPListen)
	if err != nil {
		return err
	}
	slog.Info("SIP TCP listening", "addr", s.cfg.SIP.TCPListen)
	return s.serveStream(ctx, ln, "tcp")
}

// ListenTLS serves SIP over TLS (RFC 3261 clause 26.2.1) on sip.tls_listen,
// using the certificates of the shared tls section. Framing and handling are
// those of the TCP path; only the transport label differs, which flows into
// the Via and advertised URIs so responses and route sets carry
// "SIP/2.0/TLS" and ";transport=tls".
func (s *Server) ListenTLS(ctx context.Context) error {
	if strings.TrimSpace(s.cfg.SIP.TLSListen) == "" {
		<-ctx.Done()
		return nil
	}
	tlsConf, err := tlsutil.ServerConfig(s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("sip tls listener: %w", err)
	}
	if tlsConf == nil {
		return fmt.Errorf("sip.tls_listen is set but the tls section is disabled")
	}
	ln, err := tls.Listen("tcp", s.cfg.SIP.TLSListen, tlsConf)
	if err != nil {
		return err
	}
	slog.Info("SIP TLS listening", "addr", s.cfg.SIP.TLSListen)
	return s.serveStream(ctx, ln, "tls")
}

// serveStream is the accept loop shared by the TCP and TLS listeners.
func (s *Server) serveStream(ctx context.Context, ln net.Listener, transport string) error {
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !s.serveStreamConn(ctx, conn, transport) {
			// Refuse immediately rather than accept a connection that would
			// sit unserved holding a file descriptor.
			if n := s.tcpRefused.Add(1); n%100 == 1 {
				slog.Warn("SIP TCP connection limit reached, refusing",
					"source", conn.RemoteAddr().String(), "limit", cap(s.tcpSem), "refused_total", n)
			}
			_ = conn.Close()
		}
	}
}

// serveStreamConn starts handling a connection if a slot is free, and reports
// whether it was accepted. The caller closes a refused connection.
func (s *Server) serveStreamConn(ctx context.Context, conn net.Conn, transport string) bool {
	select {
	case s.tcpSem <- struct{}{}:
		go func() {
			defer func() { <-s.tcpSem }()
			s.handleStreamConn(ctx, conn, transport)
		}()
		return true
	default:
		return false
	}
}

func (s *Server) handleStreamConn(ctx context.Context, conn net.Conn, transport string) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, sipReaderBufferBytes)
	for {
		// Reset before every message rather than once per connection, so an
		// active peer is never disconnected mid-conversation while a silent
		// one is still reclaimed.
		if err := conn.SetReadDeadline(time.Now().Add(s.streamReadTimeout())); err != nil {
			slog.Warn("SIP TCP set deadline failed", "err", err, "source", conn.RemoteAddr().String())
			return
		}
		raw, err := readSIPMessage(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				slog.Warn("SIP TCP read failed", "err", err, "source", conn.RemoteAddr().String())
			}
			return
		}
		s.handleRaw(ctx, conn.RemoteAddr().String(), transport, raw, func(resp []byte) error {
			_, err := conn.Write(resp)
			return err
		})
	}
}

func (s *Server) handlePacket(ctx context.Context, pc net.PacketConn, addr net.Addr, raw []byte, transport string) {
	s.handleRaw(ctx, addr.String(), transport, raw, func(resp []byte) error {
		_, err := pc.WriteTo(resp, addr)
		return err
	})
}

func (s *Server) handleRaw(ctx context.Context, source, transport string, raw []byte, send responder) {
	msg, err := Parse(raw)
	if err != nil {
		slog.Warn("SIP parse failed", "err", err, "source", source, "transport", transport)
		send([]byte("SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if strings.HasPrefix(strings.ToUpper(msg.StartLine), "SIP/2.0 ") {
		cseqMethod := ""
		if f := strings.Fields(msg.Header("CSeq")); len(f) >= 2 {
			cseqMethod = strings.ToUpper(f[len(f)-1])
		}
		logFn := slog.Info
		if cseqMethod == "OPTIONS" {
			logFn = slog.Debug
		}
		logFn("SIP response received",
			"status", msg.StartLine,
			"call_id", msg.Header("Call-ID"),
			"cseq", msg.Header("CSeq"),
			"source", source,
			"transport", transport,
		)
		// Client transaction layer first: stops retransmissions, ACKs
		// non-2xx INVITE finals, completes waiters. The application-level
		// pendingInvites flow below still observes the same response.
		s.dispatchClientResponse(msg)
		callID := msg.Header("Call-ID")
		cseqFields := strings.Fields(msg.Header("CSeq"))
		if len(cseqFields) >= 2 && strings.EqualFold(cseqFields[len(cseqFields)-1], "INVITE") {
			// Only deliver final responses (2xx-6xx) to pendingInvites waiters.
			// Provisional 1xx (100 Trying, 180 Ringing) must not cause the waiter
			// to exit — it must keep waiting for the real 2xx or failure code.
			statusParts := strings.Fields(msg.StartLine)
			statusCode := 0
			if len(statusParts) >= 2 {
				statusCode, _ = strconv.Atoi(statusParts[1])
			}
			if statusCode >= 200 {
				if ch, ok := s.pendingInvites.Load(callID); ok {
					select {
					case ch.(chan *Message) <- msg:
					default:
					}
				}
			}
		}
		return
	}
	s.learnRoute(msg, source, transport)

	slog.Info("SIP request received",
		"method", msg.Method,
		"call_id", msg.Header("Call-ID"),
		"from", msg.Header("From"),
		"to", msg.Header("To"),
		"ruri", msg.URI,
		"cseq", msg.Header("CSeq"),
		"event", msg.Header("Event"),
		"source", source,
		"transport", transport,
	)

	// Absorb retransmissions before any handler runs. UDP peers retransmit on
	// their own timers, and without this a duplicated INVITE re-created the
	// dialog, re-wrote the call record and re-sent every group notification.
	send, proceed := s.beginServerTransaction(msg, send)
	if !proceed {
		return
	}

	switch strings.ToUpper(msg.Method) {
	case "OPTIONS":
		slog.Debug("SIP OPTIONS received", "source", source, "transport", transport, "from", msg.Header("From"))
		s.respond(send, msg, 200, "OK", optionsHeaders(), nil)
	case "PUBLISH":
		s.handlePublish(ctx, send, msg)
	case "REGISTER":
		s.handleRegister(ctx, send, msg, source, transport)
	case "SUBSCRIBE":
		s.handleSubscribe(ctx, send, msg, source, transport)
	case "INVITE":
		if tagFrom(msg.Header("To")) != "" {
			s.handleInDialogRequest(ctx, send, msg, source, transport)
		} else {
			s.handleInvite(ctx, send, msg, source, transport)
		}
	case "ACK":
		s.handleACK(ctx, msg, source, transport)
	case "BYE":
		s.handleBYE(ctx, send, msg, source, transport)
	case "CANCEL":
		s.handleCANCEL(ctx, send, msg, source, transport)
	case "UPDATE", "INFO":
		s.handleInDialogRequest(ctx, send, msg, source, transport)
	case "REFER":
		s.handleRefer(ctx, send, msg, source, transport)
	case "MESSAGE":
		s.handleMessage(ctx, send, msg, source, transport)
	default:
		s.respond(send, msg, 405, "Method Not Allowed", optionsHeaders(), nil)
	}
}

func (s *Server) learnRoute(msg *Message, source, transport string) {
	sub := store.Subscription{
		RouteSet:   strings.Join(msg.HeadersFor("Record-Route"), "\n"),
		Transport:  transport,
		SourceAddr: source,
		TopVia:     msg.Header("Via"),
	}
	target, tp, _, err := learnedTarget(sub)
	if err != nil || target == "" {
		return
	}
	s.mu.Lock()
	s.learned[tp+"|"+target] = learnedRoute{Target: target, Transport: tp}
	s.mu.Unlock()
}

func (s *Server) sendOptions(ctx context.Context) {
	s.mu.Lock()
	routes := make([]learnedRoute, 0, len(s.learned))
	for _, route := range s.learned {
		routes = append(routes, route)
	}
	s.mu.Unlock()
	if len(routes) == 0 {
		slog.Debug("SIP OPTIONS skipped", "reason", "no learned routes")
		return
	}
	for _, route := range routes {
		branch := rfc3261BranchCookie + newToken()
		req := buildRequest("OPTIONS", s.cfg.MCX.SIPIdentity, []header{
			{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(route.Transport), advertiseHost(s.cfg), branch)},
			{"Max-Forwards", "70"},
			{"From", fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, newToken())},
			{"To", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
			{"Call-ID", newToken()},
			{"CSeq", "1 OPTIONS"},
			{"Contact", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
			{"User-Agent", productName},
		}, nil)
		// Transacted: Timer E retransmission over UDP, Timer F timeout. The
		// final response is not awaited; the keepalive only needs delivery.
		s.sendTransacted(ctx, route.Transport, route.Target, branch, "OPTIONS", []byte(req))
		slog.Debug("SIP OPTIONS sent", "target", route.Target, "transport", route.Transport)
	}
}

func (s *Server) handlePublish(ctx context.Context, send responder, msg *Message) {
	event := strings.TrimSpace(msg.Header("Event"))
	// TS 33.180 clause 9.2.1.3 allows the CSK upload to ride on the
	// PUBLISH that performs MC user authorisation as well as on the
	// initial REGISTER.
	if mcpttID := mcpttIdentityFromBody(msg); mcpttID != "" {
		s.acceptCSKUpload(msg, mcpttID)
	} else {
		s.acceptCSKUpload(msg, identityFrom(msg))
	}
	if strings.EqualFold(event, "presence") {
		// Functional alias publications share the presence event package with
		// affiliation (TS 24.379 clause 9A.2.2.2.3); the <functionalAlias>
		// element is the discriminator. Previously these were swallowed by the
		// affiliation path with a misleading 200.
		if pidfCarriesFunctionalAlias(msg) {
			s.handleFunctionalAliasPublish(ctx, send, msg)
			return
		}
		s.handlePresencePublish(ctx, send, msg)
		return
	}
	if !strings.EqualFold(event, "poc-settings") {
		s.respond(send, msg, 489, "Bad Event", nil, nil)
		return
	}
	userURI := identityFrom(msg)
	if mcpttID := mcpttIdentityFromBody(msg); mcpttID != "" {
		userURI = mcpttID
	}
	if s.cfg.SIP.Auth.RequireServiceAuthorization {
		tokenID, err := s.authorizeServicePublish(msg)
		if err != nil {
			slog.Warn("MCPTT service authorization refused", "user_uri", userURI, "err", err)
			s.respond(send, msg, 403, "Forbidden", []header{s.serviceAuthWarning()}, nil)
			return
		}
		// The authenticated identity wins over anything the body asserts.
		userURI = tokenID
	}
	if _, err := s.st.UpsertPublishedState(ctx, store.PublishedState{
		UserURI: userURI,
		Event:   event,
		Body:    string(msg.Body),
	}); err != nil {
		slog.Error("store PUBLISH state failed", "err", err, "user_uri", userURI)
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	s.respond(send, msg, 200, "OK", []header{{"SIP-ETag", sipETag()}}, nil)
}

// handlePresencePublish implements TS 24.379 clause 9.2.2.2.3: the pidf body
// carries the client's full desired affiliation set - groups listed are
// (re-)affiliated, publish-sourced affiliations absent from the body are
// de-affiliated, Expires 0 clears everything, and the N2 limit caps the set.
func (s *Server) handlePresencePublish(ctx context.Context, send responder, msg *Message) {
	userURI := identityFrom(msg)
	if mcpttID := mcpttIdentityFromBody(msg); mcpttID != "" {
		userURI = mcpttID
	}
	groups := affiliationGroupsFromPresenceBody(msg)
	if len(groups) == 0 && strings.TrimSpace(msg.Header("Expires")) != "0" {
		slog.Info("MCPTT affiliation PUBLISH ignored", "reason", "no_group", "user_uri", userURI, "call_id", msg.Header("Call-ID"))
		s.respond(send, msg, 200, "OK", []header{{"SIP-ETag", sipETag()}}, nil)
		return
	}

	// Step 5: Expires must be 4294967295 (affiliations are refreshed by
	// re-publication) or 0 (removal); anything else - including absent - is
	// 423 with Min-Expires.
	expiresRaw := strings.TrimSpace(msg.Header("Expires"))
	removeAll := false
	switch expiresRaw {
	case "4294967295":
	case "0":
		removeAll = true
	default:
		s.respond(send, msg, 423, "Interval Too Brief",
			[]header{{"Min-Expires", "4294967295"}}, nil)
		return
	}

	users, err := s.st.ListUsers(ctx)
	if err != nil {
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	userID := ""
	for _, user := range users {
		if strings.EqualFold(strings.TrimSpace(user.IMPU), strings.TrimSpace(userURI)) ||
			strings.EqualFold(strings.TrimSpace(user.MCPTTID), strings.TrimSpace(userURI)) {
			userID = user.ID
			break
		}
	}
	if userID == "" {
		slog.Warn("MCPTT affiliation PUBLISH rejected", "reason", "unknown_user", "user_uri", userURI)
		s.respond(send, msg, 403, "Forbidden", nil, nil)
		return
	}

	// Resolve the desired groups to provisioned, membered groups; unknown or
	// non-member groups drop out of the candidate set (the group-side
	// authorisation of clause 9.2.2.3 would refuse them anyway).
	allGroups, err := s.st.ListGroups(ctx)
	if err != nil {
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	var candidateIDs []string
	if !removeAll {
		seen := map[string]bool{}
		for _, groupURI := range groups {
			for _, g := range allGroups {
				if !g.Enabled || seen[g.ID] || !strings.EqualFold(strings.TrimSpace(g.URI), strings.TrimSpace(groupURI)) {
					continue
				}
				if member, err := s.st.IsGroupMember(ctx, userID, g.ID); err == nil && member {
					seen[g.ID] = true
					candidateIDs = append(candidateIDs, g.ID)
				} else {
					slog.Warn("MCPTT affiliation candidate dropped", "reason", "not_member", "user_uri", userURI, "group_uri", groupURI)
				}
			}
		}
		// N2 (clause 9.2.2.2.3: candidates beyond N2 are reduced per
		// provider policy - this server keeps the first N2 listed).
		if n2 := s.maxAffiliationsN2(); len(candidateIDs) > n2 {
			slog.Warn("MCPTT affiliation set reduced to N2", "user_uri", userURI, "requested", len(candidateIDs), "n2", n2)
			candidateIDs = candidateIDs[:n2]
		}
	}
	wanted := map[string]bool{}
	for _, id := range candidateIDs {
		wanted[id] = true
	}

	// Reconcile: listed groups affiliate; publish-sourced affiliations not
	// listed de-affiliate (step 14 a ii). Implicit affiliations from calls
	// stay until their session ends.
	existingAffs, err := s.st.ListGroupAffiliations(ctx)
	if err != nil {
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	now := time.Now().UTC()
	for _, aff := range existingAffs {
		if aff.UserID != userID {
			continue
		}
		if wanted[aff.GroupID] {
			refreshed := aff
			refreshed.State = "affiliated"
			refreshed.Source = "publish"
			refreshed.LastPublishCallID = msg.Header("Call-ID")
			refreshed.LastSeenAt = now
			if _, err := s.st.UpdateGroupAffiliation(ctx, aff.ID, refreshed); err != nil {
				slog.Warn("affiliation refresh failed", "err", err, "user_id", userID, "group_id", aff.GroupID)
			}
			delete(wanted, aff.GroupID)
			continue
		}
		if aff.Source == "publish" || removeAll {
			if err := s.st.DeleteGroupAffiliation(ctx, aff.ID); err != nil {
				slog.Warn("de-affiliation failed", "err", err, "user_id", userID, "group_id", aff.GroupID)
			} else {
				slog.Info("MCPTT de-affiliated", "user_uri", userURI, "group_id", aff.GroupID, "expires_zero", removeAll)
			}
		}
	}
	for groupID := range wanted {
		if _, err := s.st.CreateGroupAffiliation(ctx, store.GroupAffiliation{
			UserID: userID, GroupID: groupID, State: "affiliated", Source: "publish",
			LastPublishCallID: msg.Header("Call-ID"), LastSeenAt: now,
		}); err != nil {
			slog.Warn("affiliation create failed", "err", err, "user_id", userID, "group_id", groupID)
		} else {
			slog.Info("MCPTT affiliated", "user_uri", userURI, "group_id", groupID, "source", "publish")
		}
	}

	s.respond(send, msg, 200, "OK", []header{
		{"SIP-ETag", sipETag()},
		{"Expires", expiresRaw},
	}, nil)
}

// maxAffiliationsN2 is the N2 limit of TS 22.280, matching the
// <MaxAffiliationsN2> element the generated user profile advertises.
func (s *Server) maxAffiliationsN2() int {
	if s.cfg.SIP.MaxAffiliationsN2 > 0 {
		return s.cfg.SIP.MaxAffiliationsN2
	}
	return 200
}

// affiliationCount counts a user's current affiliations (for the implicit
// affiliation N2 refusal, warning "102").
func (s *Server) affiliationCount(ctx context.Context, userID string) int {
	affs, err := s.st.ListGroupAffiliations(ctx)
	if err != nil {
		return 0
	}
	count := 0
	for _, aff := range affs {
		if aff.UserID == userID {
			count++
		}
	}
	return count
}

// affiliationGroupsFromPresenceBody lists every group attribute of every
// <affiliation> element - the client's full desired set (clause 9.3.1).
func affiliationGroupsFromPresenceBody(msg *Message) []string {
	body := msg.Body
	if part := msg.Part("application/pidf+xml"); part != nil {
		body = part.Body
	}
	text := string(body)
	var out []string
	for {
		i := strings.Index(text, "<affiliation")
		if i < 0 {
			return out
		}
		text = text[i:]
		end := strings.Index(text, ">")
		if end < 0 {
			return out
		}
		if g := xmlAttr(text[:end], "group"); strings.TrimSpace(g) != "" {
			out = append(out, strings.TrimSpace(g))
		}
		text = text[end:]
	}
}

func (s *Server) handleRegister(ctx context.Context, send responder, msg *Message, source, transport string) {
	publicIdentity := identityFromHeader(msg.Header("To"))
	if publicIdentity == "" {
		publicIdentity = identityFrom(msg)
	}
	now := time.Now().UTC()
	contactRaw := msg.Header("Contact")
	expires := registerExpires(msg)
	registered := expires > 0
	isStar := strings.TrimSpace(contactRaw) == "*"
	hasMCPTT := contactHasFeature(contactRaw, "+g.3gpp.mcptt")
	isThirdPartyRegistration := strings.EqualFold(strings.TrimSpace(msg.Header("Event")), "registration")
	slog.Debug("MCPTT REGISTER parsed",
		"public_identity", publicIdentity,
		"contact", contactRaw,
		"expires_header", msg.Header("Expires"),
		"expires", expires,
		"has_mcptt_feature", hasMCPTT,
		"event", msg.Header("Event"),
		"source", source,
		"transport", transport,
	)
	if !hasMCPTT && !isThirdPartyRegistration && !isStar && registered {
		slog.Info("non-MCPTT REGISTER ignored", "public_identity", publicIdentity, "source", source, "transport", transport)
		s.respond(send, msg, 200, "OK", nil, nil)
		return
	}

	// Application-server posture: the REGISTER arriving over ISC is the
	// S-CSCF's third-party REGISTER, and the client's original REGISTER
	// travels inside its message/sip MIME body (TS 24.379 clause 7.3.2).
	// The MCPTT ID is identified from the access token in that inner
	// request's mcptt-info body (clause 7.3.1A, unprotected case; XML
	// integrity/confidentiality protection is KMS scope, carried forward)
	// and bound to the IMS public user identity on success (step 4).
	// TS 33.180 clause 9.2.1.3: the CSK is uploaded in the client's
	// initial REGISTER as an application/mikey body part. In the
	// application server posture the client's own REGISTER travels
	// inside the third party REGISTER, so both are looked at.
	s.acceptCSKUpload(msg, publicIdentity)
	// De-registration ends the security context (clause 9.2.1.2).
	if !registered {
		s.cskKeys.forget(publicIdentity)
	}

	boundMCPTTID := ""
	if s.cfg.SIP.Mode == "application_server" {
		boundMCPTTID = s.mcpttIDFromThirdPartyRegister(msg)
		if boundMCPTTID != "" {
			slog.Info("MCPTT service authorization bound",
				"public_identity", publicIdentity, "mcptt_id", boundMCPTTID)
		}
	}

	sourceIP, sourcePort := splitAddr(source)
	reg := store.Registration{
		PublicIdentity:     publicIdentity,
		MCPTTID:            boundMCPTTID,
		IMSI:               imsiFromIdentity(publicIdentity),
		ContactURI:         uriFromHeader(contactRaw),
		ContactRaw:         contactRaw,
		SourceIP:           sourceIP,
		SourcePort:         sourcePort,
		Transport:          transport,
		CallID:             msg.Header("Call-ID"),
		CSeq:               msg.Header("CSeq"),
		Registered:         registered,
		State:              "registered",
		ExpiresSeconds:     expires,
		LastSeenAt:         now,
		UserAgent:          msg.Header("User-Agent"),
		FeatureTags:        contactFeatureTags(contactRaw),
		ICSIRefs:           contactICSIRefs(contactRaw),
		SCSCFIdentity:      identityFromHeader(msg.Header("From")),
		RegistrationSource: "third_party_register",
	}
	if registered {
		reg.ExpiresAt = now.Add(time.Duration(expires) * time.Second)
		reg.LastRegisteredAt = now
		slog.Info("MCPTT client registered", "public_identity", publicIdentity, "expires", expires, "expires_at", reg.ExpiresAt, "source", source, "transport", transport)
	} else {
		reg.State = "unregistered"
		reg.ContactURI = ""
		reg.ExpiresAt = time.Time{}
		reg.LastUnregisteredAt = now
		slog.Info("MCPTT client unregistered", "public_identity", publicIdentity, "source", source, "transport", transport)
	}

	if _, err := s.st.UpsertRegistration(ctx, reg); err != nil {
		slog.Error("store registration failed", "err", err, "public_identity", publicIdentity)
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	// 3GPP TS 24.229 §5.4.1.7: the AS MUST NOT include a Contact header in its
	// 200 OK response to a third-party REGISTER (S-CSCF→AS). Contact is for the
	// UE↔P-CSCF hop only; echoing it back would be wrong.
	var regRespHeaders []header
	if !isThirdPartyRegistration {
		regRespHeaders = registerResponseHeaders(contactRaw)
	}
	s.respond(send, msg, 200, "OK", regRespHeaders, nil)
	// Clause 13.2.2: push the location reporting configuration to a freshly
	// registered client (no-op unless sip.location.report_interval_seconds
	// is set). Detached: the registration answer must not wait on it.
	if reg.Registered {
		go s.sendLocationReportingConfiguration(context.Background(), publicIdentity)
	}
}

func (s *Server) handleSubscribe(ctx context.Context, send responder, msg *Message, source, transport string) {
	event := strings.TrimSpace(msg.Header("Event"))
	// RFC 6665: the event type is the token before any event parameters -
	// TS 24.481 clause A.3 subscribes with
	// "Event: xcap-diff; diff-processing=no-patching".
	if i := strings.IndexByte(event, ';'); i >= 0 {
		event = strings.TrimSpace(event[:i])
	}
	// Only known event packages are served. Defaulting the absent or unknown
	// case to affiliation answered subscriptions to other packages (functional
	// alias determination, conference) with affiliation data - a silent
	// corruption the audit flagged. RFC 6665 wants 489 with the supported
	// packages listed in Allow-Events.
	switch strings.ToLower(event) {
	case "presence", "xcap-diff", "affiliation", "conference":
	default:
		s.respond(send, msg, 489, "Bad Event",
			[]header{{"Allow-Events", "presence, xcap-diff"}}, nil)
		return
	}
	// Use the IMS-validated SIP identity (P-Asserted-Identity / From header) as the
	// authoritative subscriber URI. The <mcptt-request-uri> in the MCPTT-Info body
	// reflects the client's IDMS-derived self-identity, which may be wrong if the
	// IDMS shim returned a different user's MCPTT ID (e.g. on a device's first boot
	// before the IP→user mapping is established).
	subscriberURI := identityFrom(msg)
	selectors := xcapResourceListSelectors(msg)
	localTag := newToken()
	remoteTag := tagFrom(msg.Header("From"))

	// RFC 3265 §3.1: negotiate subscription lifetime from the requested Expires.
	// Cap at 3600. Expires=0 is an explicit unsubscribe — respond and stop.
	reqExpires := 3600
	if v := strings.TrimSpace(msg.Header("Expires")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			reqExpires = n
		}
	}
	if reqExpires > 3600 {
		reqExpires = 3600
	}
	// Conference event package (TS 24.379 clause 10.1.3.4.1): the
	// subscriber must be a current participant of the group session named in
	// the mcptt-info body.
	confGroupURI := ""
	if strings.EqualFold(event, "conference") {
		confGroupURI = conferenceGroupURI(msg)
		if confGroupURI == "" || !s.isSessionParticipant(ctx, confGroupURI, subscriberURI) {
			slog.Warn("conference subscription refused", "subscriber", subscriberURI, "group_uri", confGroupURI)
			s.respond(send, msg, 403, "Forbidden", nil, nil)
			return
		}
		selectors = []string{confGroupURI}
	}
	if reqExpires == 0 {
		// Unsubscribe: drop the change-NOTIFY registrations (RFC 5875 /
		// conference).
		s.xcapSubs.Delete(msg.Header("Call-ID"))
		s.registerConferenceSubscription(store.Subscription{CallID: msg.Header("Call-ID")}, "", 0)
		s.respondTagged(send, msg, 200, "OK", localTag, []header{{"Expires", "0"}}, nil)
		return
	}

	sub, err := s.st.CreateSubscription(ctx, store.Subscription{
		CallID:        msg.Header("Call-ID"),
		Event:         event,
		SubscriberURI: subscriberURI,
		TargetURI:     msg.URI,
		Selectors:     selectors,
		LocalTag:      localTag,
		RemoteTag:     remoteTag,
		RouteSet:      strings.Join(msg.HeadersFor("Record-Route"), "\n"),
		RemoteTarget:  uriFromHeader(msg.Header("Contact")),
		Transport:     transport,
		SourceAddr:    source,
		TopVia:        msg.Header("Via"),
		State:         "active",
		ExpiresAt:     time.Now().UTC().Add(time.Duration(reqExpires) * time.Second),
	})
	if err != nil {
		slog.Error("store subscription failed", "err", err)
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	sub.Selectors = selectors
	// Change-triggered NOTIFY registries: the subscription is tracked until
	// it unsubscribes or the server restarts.
	s.registerXCAPSubscription(sub, reqExpires)
	if strings.EqualFold(event, "conference") {
		s.registerConferenceSubscription(sub, confGroupURI, reqExpires)
	}
	// Cache subscription route for RX INVITE delivery: the mo@pcscf Route entry
	// (with the UE's SIP outbound ftag) lets P-CSCF deliver the INVITE over the
	// UE's existing outbound TCP connection instead of opening a new TCP SYN.
	if sub.SubscriberURI != "" {
		s.ueSubRoute.Store(strings.ToLower(strings.TrimSpace(sub.SubscriberURI)), sub)
	}

	// Cache UE device IP → subscriber MCPTT ID so the IDMS shim and UE init config
	// can return the correct identity for this device on subsequent connections.
	if ueHost := hostFromContactURI(msg.Header("Contact")); ueHost != "" && subscriberURI != "" {
		if err := s.st.SetUEContactIP(ctx, ueHost, subscriberURI); err != nil {
			slog.Warn("UE contact IP cache failed", "ip", ueHost, "mcptt_id", subscriberURI, "err", err)
		}
	}

	if strings.EqualFold(event, "xcap-diff") {
		slog.Info("SIP xcap-diff subscription selectors", "subscription_type", xcapSubscriptionType(selectors), "call_id", sub.CallID, "subscriber", sub.SubscriberURI, "selectors", strings.Join(selectors, ","))
	}
	s.respondTagged(send, msg, 200, "OK", localTag, []header{{"Expires", strconv.Itoa(reqExpires)}}, nil)

	if err := s.sendNotify(ctx, sub, msg, send); err != nil {
		slog.Warn("initial NOTIFY failed", "err", err, "call_id", sub.CallID, "event", sub.Event)
	}
}

func (s *Server) handleInvite(ctx context.Context, send responder, msg *Message, source, transport string) {
	localTag := newToken()
	remoteTag := tagFrom(msg.Header("From"))
	callID := msg.Header("Call-ID")
	// The calling user's identity must come from the SIP From/P-Asserted-Identity
	// header, not from <mcptt-request-uri> in the mcptt-info body: for INVITEs
	// that element carries the MCPTT ID associated with the *addressed*
	// user/group (e.g. the target group for a group call), not the originator.
	// Overwriting initiatorURI with it (as PUBLISH/SUBSCRIBE handlers correctly
	// do for their own request semantics) breaks admitGroupInvite's membership
	// lookup, which expects the calling user's IMPU/MCPTT ID.
	initiatorURI := identityFrom(msg)
	mcpttID := mcpttIdentityFromBody(msg)
	remoteTarget := uriFromHeader(msg.Header("Contact"))
	routeSet := strings.Join(msg.HeadersFor("Record-Route"), "\n")
	contactURI := s.advertisedSIPURI(transport)
	recordRoute := s.recordRouteURI(transport)
	offer, _ := s.sdpOffer(msg)
	sdpInfo := parseSDP(offer)
	groupURI := groupURIFromInvite(msg)
	if groupURI == "" {
		// For AS-routed group calls the SIP Request-URI is the AS itself, not the
		// group. The MCPTT-Info body's <mcptt-request-uri> carries the addressed
		// group identity in that case — use it as the group URI so admission and
		// relay lookups have the correct group to work with.
		groupURI = mcpttID
	}
	if groupURI == "" {
		// A temporary group identity (TS 24.379 clause 16.2) need not look
		// like a group URI, so an active regroup is matched explicitly.
		if _, isTGI := s.regroups.get(strings.TrimSpace(msg.URI)); isTGI {
			groupURI = strings.TrimSpace(msg.URI)
		}
	}
	// TS 24.379 clause 17: an INVITE whose mcptt-info carries
	// <session-type>adhoc</session-type> is an ad hoc group call; its
	// membership comes from the request, not from group documents, so it takes
	// its own controlling path (clause 17.4.2.2).
	// A pre-established session establishment INVITE targets its own PSI
	// (TS 24.379 clause 8.2.2) and takes none of the call paths.
	if s.isPreEstablishedInvite(msg) {
		s.handlePreEstablishedInvite(ctx, send, msg, source, transport)
		return
	}
	switch sessionTypeFromBody(msg) {
	case "adhoc":
		s.handleAdhocInvite(ctx, send, msg, source, transport)
		return
	case "private":
		// TS 24.379 clause 11.1.1: private call - the callee comes from the
		// resource-lists body and is actually invited before the caller's
		// final response.
		s.handlePrivateInvite(ctx, send, msg, source, transport)
		return
	case "first-to-answer":
		// TS 24.379 clause 11.1.1: parallel candidate legs, first 200 wins,
		// losers released with "not selected for call".
		s.handleFirstToAnswerInvite(ctx, send, msg, source, transport)
		return
	}
	// Originating participating function, TS 24.379 clause 10.1.1.3.1.1
	// steps 2/2a: the calling identity must resolve to a served user. The
	// binding of clause 7.3 is approximated by the provisioned user table
	// until service authorisation writes real bindings.
	if groupURI != "" && !s.servedUserExists(ctx, initiatorURI) {
		slog.Warn("MCPTT INVITE from unknown user rejected",
			"call_id", callID, "initiator", initiatorURI,
			"warning", "141 user unknown to the participating function")
		s.respond(send, msg, 404, "Not Found",
			[]header{s.mcpttWarning("141 user unknown to the participating function")}, nil)
		return
	}

	// A group fused into a regroup no longer takes calls of its own
	// (TS 24.379 clause 10.1.1.4.2 / 10.1.2.4.1.1 step 4 c i).
	if tgi, regrouped := s.regroups.regroupedInto(groupURI); regrouped {
		slog.Info("MCPTT INVITE to a regrouped constituent refused",
			"call_id", callID, "group_uri", groupURI, "tgi", tgi)
		s.respond(send, msg, 403, "Forbidden",
			[]header{s.mcpttWarning("148 group is regrouped")}, nil)
		return
	}
	// A call on a temporary group identity spans the constituent groups.
	regroupConstituents := s.regroupConstituents(groupURI)

	// The controlling function of the target group decides admission
	// (TS 24.379 clause 6.3.3); this participating side only relays the
	// verdict. Resolution is per group so a remotely homed group binds to the
	// SIP-speaking implementation of the same seam.
	controlling := s.controllingFor(groupURI)
	call := originatingGroupCall{
		CallID:       callID,
		InitiatorURI: initiatorURI,
		GroupURI:     groupURI,
		SDP:          sdpInfo,
	}
	if rc, isRemote := controlling.(remoteControlling); isRemote {
		// A remotely homed group: this server is purely the originating
		// participating function, and the whole exchange is relayed
		// (clauses 10.1.1.3.1.1, 6.3.2.1.3, 6.3.2.1.5.2).
		s.uasInvites.Store(callID, &uasInviteState{msg: msg, send: send, tag: localTag})
		s.respond(send, msg, 100, "Trying", nil, nil)
		s.relayToRemoteControlling(ctx, send, msg, rc, call, localTag, transport)
		return
	}
	if len(regroupConstituents) > 0 {
		if verdict := s.admitRegroupInvite(ctx, initiatorURI, regroupConstituents); !verdict.Admitted {
			slog.Warn("MCPTT regroup INVITE rejected", "call_id", callID,
				"initiator", initiatorURI, "tgi", groupURI, "warning", verdict.Warning)
			var extra []header
			if verdict.Warning != "" {
				extra = append(extra, s.mcpttWarning(verdict.Warning))
			}
			s.respond(send, msg, verdict.Status, verdict.Reason, extra, nil)
			return
		}
	} else if verdict := controlling.AdmitOriginatingCall(ctx, call); !verdict.Admitted {
		slog.Warn("MCPTT group INVITE rejected",
			"call_id", callID,
			"initiator", initiatorURI,
			"mcptt_request_uri", mcpttID,
			"group_uri", groupURI,
			"status", verdict.Status,
			"reason", verdict.Reason,
			"warning", verdict.Warning,
		)
		var extra []header
		if verdict.Warning != "" {
			extra = append(extra, s.mcpttWarning(verdict.Warning))
		}
		s.respond(send, msg, verdict.Status, verdict.Reason, extra, nil)
		return
	}
	// TS 24.481 <on-network-invite-members>: absent/false marks a chat group
	// (clause 7.2.4.2), which members join by calling in - no fan-out.
	group := s.groupByURI(ctx, groupURI)
	isChat := group != nil && group.ChatGroup

	// MCPTT emergency / imminent peril handling (clauses 6.3.3.1.13.2/.14,
	// 10.1.1.4.2 steps 4-6, 10.1.2.4.1.1 steps 7-9).
	emergencyReq := mcpttInfoFlagTrue(msg, "emergency-ind")
	imminentReq := mcpttInfoFlagTrue(msg, "imminentperil-ind")
	if emergencyReq || imminentReq {
		if !s.emergencyCallAuthorised(ctx, initiatorURI, group) {
			kind := "emergency"
			if !emergencyReq {
				kind = "imminent peril"
			}
			slog.Warn("MCPTT priority group call not authorised",
				"call_id", callID, "initiator", initiatorURI, "group_uri", groupURI, "kind", kind)
			body, contentType := priorityRejectBody()
			s.respond(send, msg, 403, "Forbidden",
				[]header{{"Content-Type", contentType}}, []byte(body))
			return
		}
		if emergencyReq {
			// In-progress emergency state set; an emergency clears any
			// imminent peril state (10.1.2.4.1.1 step 14 c vii).
			s.setGroupPriorityState(groupURI, "emergency")
		} else if s.groupPriorityState(groupURI) != "emergency" {
			s.setGroupPriorityState(groupURI, "imminent")
		}
		slog.Info("MCPTT priority group call accepted",
			"call_id", callID, "group_uri", groupURI, "state", s.groupPriorityState(groupURI))
	} else if rp := strings.TrimSpace(msg.Header("Resource-Priority")); rp != "" {
		// Step 9: a Resource-Priority header claiming a priority level without
		// the matching indication and without the group being in that state is
		// refused.
		if (strings.EqualFold(rp, resourcePriorityEmergency) && s.groupPriorityState(groupURI) != "emergency") ||
			(strings.EqualFold(rp, resourcePriorityImminent) && s.groupPriorityState(groupURI) == "") {
			slog.Warn("MCPTT INVITE with unearned Resource-Priority rejected",
				"call_id", callID, "resource_priority", rp, "group_uri", groupURI)
			s.respond(send, msg, 403, "Forbidden", nil, nil)
			return
		}
	}
	if isChat {
		// Clause 10.1.2.4.1.1 step 12: the <on-network-max-participant-count>
		// (the generated group document carries 200) bounds the session.
		if peers, err := s.st.ListCallsByGroup(ctx, groupURI); err == nil && len(peers) >= chatMaxParticipantCount {
			s.respond(send, msg, 486, "Busy Here",
				[]header{s.mcpttWarning("122 too many participants")}, nil)
			return
		}
	}
	if _, err := s.st.CreateDialog(ctx, store.Dialog{
		CallID:          callID,
		LocalTag:        localTag,
		RemoteTag:       remoteTag,
		FromURI:         identityFromHeader(msg.Header("From")),
		ToURI:           identityFromHeader(msg.Header("To")),
		RequestURI:      msg.URI,
		IMPU:            identityFromHeader(msg.Header("From")),
		MCPTTID:         mcpttID,
		Method:          "INVITE",
		State:           "confirmed",
		RouteSet:        routeSetWithAS(routeSet, recordRoute),
		RemoteTarget:    remoteTarget,
		RecordRouteUsed: s.cfg.SIP.RecordRoute,
		LocalCSeq:       1,
		RemoteCSeq:      cseqNumber(msg.Header("CSeq")),
		LastMethod:      "INVITE",
		LastStatus:      200,
		Transport:       transport,
		SourceAddr:      source,
		TopVia:          msg.Header("Via"),
	}); err != nil {
		slog.Warn("store dialog failed", "err", err, "call_id", callID)
	}
	slog.Info("MCPTT INVITE received",
		"call_id", callID,
		"initiator", initiatorURI,
		"mcptt_request_uri", mcpttID,
		"target", msg.URI,
		"has_sdp", offer != "",
		"audio", mediaLogValue(sdpInfo.Audio),
		"floor_control", mediaLogValue(sdpInfo.FloorControl),
		"source", source,
		"transport", transport,
	)
	// RFC 3261 §9.2: track this INVITE so CANCEL can send a 487 if no final
	// response has been sent yet.
	s.uasInvites.Store(callID, &uasInviteState{msg: msg, send: send, tag: localTag})
	s.respond(send, msg, 100, "Trying", nil, nil)
	s.respondTagged(send, msg, 180, "Ringing", localTag, inviteResponseHeaders(contactURI, recordRoute, msg.HeadersFor("Record-Route"), ""), nil)

	body, contentType := s.sdpAnswer(msg)
	now := time.Now().UTC()
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:               callID,
		State:                "answered",
		InitiatorURI:         initiatorURI,
		TargetURI:            msg.URI,
		GroupURI:             groupURI,
		MCPTTID:              mcpttID,
		RemoteTarget:         remoteTarget,
		RouteSet:             routeSet,
		LocalTag:             localTag,
		RemoteTag:            remoteTag,
		Transport:            transport,
		SourceAddr:           source,
		AudioIP:              sdpInfo.Audio.ConnectionIP,
		AudioPort:            sdpInfo.Audio.Port,
		AudioProto:           sdpInfo.Audio.Proto,
		AudioPayloads:        sdpInfo.Audio.Payloads,
		FloorControlIP:       sdpInfo.FloorControl.ConnectionIP,
		FloorControlPort:     sdpInfo.FloorControl.Port,
		FloorControlProto:    sdpInfo.FloorControl.Proto,
		FloorControlPayloads: sdpInfo.FloorControl.Payloads,
		MediaAttributes:      sdpInfo.Audio.Attributes,
		FloorControlAttrs:    sdpInfo.FloorControl.Attributes,
		LocalAudioPort:       s.cfg.Media.AudioPort,
		LocalRTCPPort:        s.cfg.Media.RTCPPort,
		LocalFloorPort:       s.cfg.Media.FloorControlPort,
		SDPOffer:             offer,
		SDPAnswer:            string(body),
		AnsweredAt:           now,
	}); err != nil {
		slog.Warn("store call failed", "err", err, "call_id", callID)
	}
	if sdpGrantsImplicitFloor(body) {
		if _, err := s.st.UpdateCallFloorState(ctx, callID, store.FloorStateUpdate{
			State:   "granted",
			Event:   "sdp_granted",
			Subtype: 1,
			At:      now,
		}); err != nil {
			slog.Warn("store SDP floor grant failed", "err", err, "call_id", callID)
		} else {
			slog.Info("MCPTT floor granted by SDP", "call_id", callID)
		}
	}
	// TS 24.379 clause 10.1.1.4.2 step 14 e: the session identity is
	// allocated when the prearranged group session is created, before any
	// member is invited, so the member legs can carry it (clause 6.3.2.2.3
	// item 4 d).
	var sessionURI string
	if isChat {
		// Clause 10.1.2.4.1.1 step 11a: the session identity belongs to the
		// chat session, created by the first joiner and shared by later ones.
		sessionURI = s.chatSessionIdentity(groupURI, callID)
	} else {
		sessionURI = s.allocateSessionIdentity(callID)
	}

	// TS 24.379 clause 10.1.1.4.2 step 14 g v: the controlling function
	// invites the group members before answering the originating leg. This is
	// the unacknowledged flow; the acknowledged variant (TNG1, clause 6.3.3.3)
	// waits for required members' answers and arises only when the group
	// document marks members <on-network-required>, which generated documents
	// do not yet. A chat group has no fan-out: members join themselves
	// (clause 10.1.2.4.1.1).
	switch {
	case len(regroupConstituents) > 0:
		// The regroup's members are the union of the constituent groups'
		// affiliated members (clause 16.2 with 10.1.1.4.2 step 14 g v).
		s.establishRegroupLegs(context.Background(), callID, groupURI, initiatorURI, regroupConstituents, sdpInfo)
	case groupURI != "" && !isChat:
		controlling.EstablishGroupLegs(call)
	}

	// SIP 200 (OK) per clause 6.3.3.2.3.2: the Contact carries the MCPTT
	// session identity (clause 4.5) with the isfocus, g.3gpp.mcptt and
	// g.3gpp.icsi-ref feature tags; P-Asserted-Identity is the controlling
	// function's public service identity; Session-Expires with refresher=uac
	// and the timer option tag per RFC 4028; tdialog, norefersub, explicitsub
	// and nosub advertised per items 8-10.
	headers := []header{
		{"Contact", fmt.Sprintf("<%s>;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mcptt\";isfocus", sessionURI)},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"Session-Expires", "1800;refresher=uac"},
		{"Require", "timer"},
		{"Supported", "tdialog, norefersub, explicitsub, nosub"},
		{"Allow", allowValue},
	}
	headers = append(recordRouteHeaders(recordRoute, msg.HeadersFor("Record-Route")), headers...)
	if contentType != "" {
		headers = append(headers, header{"Content-Type", contentType})
	}
	// RFC 4028 supervision starts with the answer (clause 6.3.3.2.3.2 item 6).
	s.markSessionAnswered(ctx, callID)
	s.NotifyConferenceChange(groupURI)
	// Final response committed — CANCEL can no longer trigger a 487.
	s.uasInvites.Delete(callID)
	s.respondTagged(send, msg, 200, "OK", localTag, headers, body)
}

func (s *Server) handleACK(ctx context.Context, msg *Message, source, transport string) {
	callID := msg.Header("Call-ID")
	fromTag := tagFrom(msg.Header("From"))
	toTag := tagFrom(msg.Header("To"))
	dlg, err := s.st.FindDialog(ctx, callID, fromTag, toTag)
	matched := err == nil && dlg != nil
	slog.Info("SIP ACK received", "call_id", callID, "from_tag", fromTag, "to_tag", toTag, "matched", matched, "source", source, "transport", transport)
	if !matched {
		return
	}
	s.st.UpdateDialogState(ctx, callID, "confirmed")
	if err := s.st.UpdateCallState(ctx, callID, "established"); err != nil {
		slog.Warn("update call state failed", "err", err, "call_id", callID, "state", "established")
	}
}

func (s *Server) handleBYE(ctx context.Context, send responder, msg *Message, source, transport string) {
	callID := msg.Header("Call-ID")
	fromTag := tagFrom(msg.Header("From"))
	toTag := tagFrom(msg.Header("To"))
	dlg, err := s.st.FindDialog(ctx, callID, fromTag, toTag)
	if err != nil {
		slog.Warn("SIP BYE dialog lookup failed", "err", err, "call_id", callID)
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	if dlg == nil {
		slog.Warn("SIP BYE received", "call_id", callID, "from", identityFromHeader(msg.Header("From")), "to", identityFromHeader(msg.Header("To")), "matched", false, "reason", "no_dialog", "source", source, "transport", transport)
		s.respond(send, msg, 481, "Call/Transaction Does Not Exist", nil, nil)
		return
	}

	slog.Info("SIP BYE received", "call_id", callID, "from", identityFromHeader(msg.Header("From")), "to", identityFromHeader(msg.Header("To")), "dialog", dlg.ID, "matched", true, "action", "terminate_call", "source", source, "transport", transport)
	if err := s.st.UpdateDialogState(ctx, callID, "terminating"); err != nil {
		slog.Warn("update dialog state failed", "err", err, "call_id", callID, "state", "terminating")
	}
	if err := s.st.UpdateCallState(ctx, callID, "terminating"); err != nil {
		slog.Warn("update call state failed", "err", err, "call_id", callID, "state", "terminating")
	}
	s.respond(send, msg, 200, "OK", nil, nil)
	if err := s.st.UpdateDialogState(ctx, callID, "terminated"); err != nil {
		slog.Warn("update dialog state failed", "err", err, "call_id", callID, "state", "terminated")
	}
	if err := s.st.UpdateCallState(ctx, callID, "terminated"); err != nil {
		slog.Warn("update call state failed", "err", err, "call_id", callID, "state", "terminated")
	}
	slog.Info("SIP BYE completed", "call_id", callID, "status", 200, "dialog_state", "terminated")
	s.logCallMediaSummary(ctx, callID)

	// Tear down AS-initiated RX legs for this group call.
	call, _ := s.st.GetCall(ctx, callID)
	if call != nil && call.GroupURI != "" {
		s.controllingFor(call.GroupURI).ReleaseGroupLegs(call.GroupURI, callID)
		// A chat session ends when its last participant leaves
		// (TS 24.379 clause 10.1.2.4.1.2).
		s.releaseChatSessionIfEmpty(ctx, call.GroupURI)
		// The in-progress priority state clears with the group's last leg
		// (TNG2 supervision of clause 6.3.3.1.16 would otherwise bound it).
		if peers, err := s.st.ListCallsByGroup(ctx, call.GroupURI); err == nil && len(peers) == 0 {
			s.setGroupPriorityState(call.GroupURI, "")
		}
		// The participant set shrank (clause 10.1.3.4.2).
		s.NotifyConferenceChange(call.GroupURI)
	}
	if call != nil {
		s.releasePreEstablished(callID)
	}
}

func (s *Server) logCallMediaSummary(ctx context.Context, callID string) {
	call, err := s.st.GetCall(ctx, callID)
	if err != nil {
		slog.Warn("call media summary lookup failed", "call_id", callID, "err", err)
		return
	}
	if call == nil {
		return
	}
	durationMS := int64(0)
	if !call.EstablishedAt.IsZero() && !call.TerminatedAt.IsZero() && call.TerminatedAt.After(call.EstablishedAt) {
		durationMS = call.TerminatedAt.Sub(call.EstablishedAt).Milliseconds()
	}
	lossPercent := float64(0)
	if call.RTPExpectedPackets > 0 {
		lossPercent = float64(call.RTPLostPackets) * 100 / float64(call.RTPExpectedPackets)
	}
	slog.Info("MCPTT media summary",
		"call_id", callID,
		"duration_ms", durationMS,
		"audio_remote", mediaEndpoint(call.AudioIP, call.AudioPort),
		"rtp_packets", call.RTPPackets,
		"rtp_bytes", call.RTPBytes,
		"rtp_rejected_packets", call.RTPRejectedPackets,
		"rtp_rejected_bytes", call.RTPRejectedBytes,
		"rtcp_packets", call.RTCPPackets,
		"floor_packets", call.FloorPackets,
		"floor_state", call.FloorState,
		"floor_event", call.FloorLastEvent,
		"payload_type", call.RTPPayloadType,
		"ssrc", call.RTPSSRC,
		"first_sequence", call.RTPFirstSequence,
		"last_sequence", call.RTPLastSequence,
		"expected_packets", call.RTPExpectedPackets,
		"lost_packets", call.RTPLostPackets,
		"loss_percent", fmt.Sprintf("%.2f", lossPercent),
		"jitter", fmt.Sprintf("%.2f", call.RTPJitter),
	)
}

func mediaEndpoint(host string, port int) string {
	if host == "" || port == 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (s *Server) handleCANCEL(ctx context.Context, send responder, msg *Message, source, transport string) {
	callID := msg.Header("Call-ID")
	slog.Info("SIP CANCEL received", "call_id", callID, "source", source, "transport", transport)
	s.st.UpdateDialogState(ctx, callID, "terminated")
	if err := s.st.UpdateCallState(ctx, callID, "cancelled"); err != nil {
		slog.Warn("update call state failed", "err", err, "call_id", callID, "state", "cancelled")
	}
	// RFC 3261 §9.2: 200 to CANCEL first, then 487 to the INVITE if the INVITE
	// has not yet received a final response.
	s.respond(send, msg, 200, "OK", nil, nil)
	if p, ok := s.uasInvites.LoadAndDelete(callID); ok {
		inv := p.(*uasInviteState)
		s.respondTagged(inv.send, inv.msg, 487, "Request Terminated", inv.tag, nil, nil)
	}
	// A relayed INVITE still in flight toward a remote controlling function
	// is cancelled there too (RFC 3261 clause 9.1; TS 24.379 relay posture).
	s.relayRemoteCancel(callID)
}

func (s *Server) handleInDialogRequest(ctx context.Context, send responder, msg *Message, source, transport string) {
	callID := msg.Header("Call-ID")
	fromTag := tagFrom(msg.Header("From"))
	toTag := tagFrom(msg.Header("To"))
	dlg, err := s.st.FindDialog(ctx, callID, fromTag, toTag)
	if err != nil {
		slog.Warn("in-dialog request lookup failed", "method", msg.Method, "err", err, "call_id", callID)
		s.respond(send, msg, 500, "Server Internal Error", nil, nil)
		return
	}
	if dlg == nil {
		slog.Warn("in-dialog request has no dialog", "method", msg.Method, "call_id", callID, "from_tag", fromTag, "to_tag", toTag, "source", source, "transport", transport)
		s.respond(send, msg, 481, "Call/Transaction Does Not Exist", nil, nil)
		return
	}
	slog.Info("in-dialog request received", "method", msg.Method, "call_id", callID, "dialog", dlg.ID, "source", source, "transport", transport)
	// RFC 4028 UAS behavior: a re-INVITE or UPDATE inside the dialog is a
	// session refresh - the response repeats Session-Expires and the
	// supervision clock restarts (TS 24.379 clause 6.3.3.2.3.2 item 6).
	refresh := strings.EqualFold(msg.Method, "INVITE") || strings.EqualFold(msg.Method, "UPDATE")
	// An in-dialog re-INVITE carrying a priority indication upgrades or
	// cancels the call's emergency/imminent peril state (TS 24.379 clause
	// 10.1.2.4.1.2 and siblings).
	if strings.EqualFold(msg.Method, "INVITE") && s.handlePriorityReInvite(ctx, send, msg) {
		return
	}
	if refresh {
		s.markSessionAnswered(ctx, callID)
	}
	if strings.EqualFold(msg.Method, "INVITE") {
		body, contentType := s.sdpAnswer(msg)
		headers := []header{
			{"Contact", fmt.Sprintf("<%s>", s.advertisedSIPURI(transport))},
			{"Allow", allowValue},
			{"Session-Expires", sessionExpiresHeader},
			{"Require", "timer"},
		}
		if contentType != "" {
			headers = append(headers, header{"Content-Type", contentType})
		}
		s.respond(send, msg, 200, "OK", headers, body)
		return
	}
	headers := []header{{"Allow", allowValue}}
	if refresh {
		headers = append(headers, header{"Session-Expires", sessionExpiresHeader}, header{"Require", "timer"})
	}
	s.respond(send, msg, 200, "OK", headers, nil)
}

// sendGroupCallNotifications sends an outbound INVITE to every registered group
// member except the TX initiator, establishing an RX leg so the relay can forward
// the floor-holder's RTP to them.
func (s *Server) sendGroupCallNotifications(ctx context.Context, txCallID, groupURI, initiatorURI string, txSDP sdpInfo) {
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		slog.Warn("group notify: list groups failed", "err", err)
		return
	}
	groupID := ""
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g.URI), strings.TrimSpace(groupURI)) {
			groupID = g.ID
			break
		}
	}
	if groupID == "" {
		return
	}

	users, err := s.st.ListUsers(ctx)
	if err != nil {
		slog.Warn("group notify: list users failed", "err", err)
		return
	}
	userByID := make(map[string]store.User, len(users))
	for _, u := range users {
		userByID[u.ID] = u
	}

	memberships, err := s.st.ListGroupMemberships(ctx)
	if err != nil {
		slog.Warn("group notify: list memberships failed", "err", err)
		return
	}

	regs, err := s.st.ListRegistrations(ctx)
	if err != nil {
		slog.Warn("group notify: list registrations failed", "err", err)
		return
	}
	regByImpu := make(map[string]store.Registration, len(regs))
	for _, r := range regs {
		if r.Registered {
			regByImpu[strings.TrimSpace(r.PublicIdentity)] = r
		}
	}

	// Pick the best payload type from the TX SDP offer to use in the RX offer.
	audioPayload := "114 96 9 0 8"
	if len(txSDP.Audio.Payloads) > 0 {
		audioPayload = strings.Join(txSDP.Audio.Payloads, " ")
	}

	// Terminate any stale call records for this group before sending new RX INVITEs:
	// - Old AS-initiated RX legs (previous round of calls)
	// - Old TX legs from the same initiator (same device calling again without hanging up)
	// This prevents relayRTP from targeting stale records and echoing audio.
	for _, peer := range func() []store.MCPTTCall {
		p, _ := s.st.ListCallsByGroup(ctx, groupURI)
		return p
	}() {
		if peer.CallID == txCallID {
			continue
		}
		asInitiated := strings.EqualFold(strings.TrimSpace(peer.InitiatorURI), strings.TrimSpace(s.cfg.MCX.SIPIdentity))
		sameInitiator := strings.EqualFold(strings.TrimSpace(peer.InitiatorURI), strings.TrimSpace(initiatorURI))
		if !asInitiated && !sameInitiator {
			continue
		}
		if err := s.st.UpdateCallState(ctx, peer.CallID, "terminated"); err != nil {
			slog.Warn("group notify: stale leg cleanup failed", "call_id", peer.CallID, "err", err)
		} else {
			slog.Info("group notify: stale leg terminated", "call_id", peer.CallID, "initiator", peer.InitiatorURI, "member", peer.TargetURI)
		}
		if asInitiated {
			go s.sendRXBYE(context.Background(), peer)
		}
	}

	for _, m := range memberships {
		if m.GroupID != groupID {
			continue
		}
		user, ok := userByID[m.UserID]
		if !ok || !user.Enabled {
			continue
		}
		impu := strings.TrimSpace(user.IMPU)
		if impu == "" {
			impu = strings.TrimSpace(user.MCPTTID)
		}
		if strings.EqualFold(impu, strings.TrimSpace(initiatorURI)) {
			continue
		}
		reg, ok := regByImpu[impu]
		if !ok || !reg.Registered {
			slog.Debug("group notify: member not registered, skip", "member", impu)
			continue
		}
		// TS 24.379 clause 10.1.1.3.2 step 3: without the member's published
		// Answer-Mode Indication the terminating participating function must
		// not invite them (a standalone T-PF would answer 480 with warning
		// "146 T-PF unable to determine the service settings for the called
		// user"; in-process that verdict is a skipped leg).
		mode := s.answerModeFor(ctx, impu)
		if mode == answerModeUnknown {
			slog.Warn("group notify: member has no usable poc-settings, leg not established",
				"member", impu, "warning", "146 T-PF unable to determine the service settings for the called user")
			continue
		}
		s.sendRXInvite(context.Background(), txCallID, groupURI, initiatorURI, impu, audioPayload, "prearranged", reg, mode, nil)
	}
}

// sendRXInvite builds and sends a terminating leg toward a member, returning
// the leg's Call-ID. done, when non-nil, receives the leg outcome
// (established or not) — the private and first-to-answer call flows answer
// their originator only after a callee answers (TS 24.379 clause 11.1.1.4.2),
// unlike the group flow which only orders invites before its 200.
func (s *Server) sendRXInvite(ctx context.Context, txCallID, groupURI, initiatorURI, memberImpu, audioPayload, sessionType string, reg store.Registration, mode answerMode, done chan bool) string {
	// Call-ID is token-only (no @host) to save ~18 bytes — RFC 3261 allows bare tokens.
	callID := newToken()
	localTag := newToken()

	ch := make(chan *Message, 1)
	s.pendingInvites.Store(callID, ch)

	host := strings.TrimSpace(s.cfg.Media.AdvertiseHost)
	if host == "" {
		host = strings.TrimSpace(s.cfg.SIP.AdvertiseHost)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	audioPort := s.cfg.Media.AudioPort
	if audioPort == 0 {
		audioPort = 40000
	}
	rtcpPort := s.cfg.Media.RTCPPort
	if rtcpPort == 0 {
		rtcpPort = audioPort + 1
	}
	floorPort := s.cfg.Media.FloorControlPort
	if floorPort == 0 {
		floorPort = 40002
	}
	// SDP offer toward the terminating member: audio plus the MCPTT floor
	// control media line (TS 24.380 clause 4.3), so the member negotiates the
	// control channel rather than the audio-only offer a previous client bug
	// forced.
	sdpBody := fmt.Sprintf(
		"v=0\r\no=- 0 0 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP %s\r\n"+
			"a=sendrecv\r\n"+
			"m=application %d udp MCPTT\r\n",
		host, host, audioPort, audioPayload, floorPort,
	)

	// MCPTT info body classifying the terminating leg (TS 24.379 clause
	// 15.1.4, mcpttinfo schema in Annex F.1): "prearranged" for group-document
	// calls, "adhoc" for clause 17 legs (17.4.2.1.1).
	callerURI := initiatorURI
	if callerURI == "" {
		callerURI = s.cfg.MCX.SIPIdentity
	}
	var mcpttInfoBody string
	if sessionType == "private" || sessionType == "first-to-answer" {
		// Clause 11.1.1.4.1 step 4: the <mcptt-request-uri> carries the
		// invited user's MCPTT ID; private and first-to-answer calls have no
		// calling group.
		mcpttInfoBody = fmt.Sprintf(
			`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0">`+
				`<mcptt-Params>`+
				`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
				`<mcptt-calling-user-id><mcpttURI>%s</mcpttURI></mcptt-calling-user-id>`+
				`<session-type>%s</session-type>`+
				`</mcptt-Params>`+
				`</mcpttinfo>`,
			memberImpu, callerURI, sessionType,
		)
	} else {
		mcpttInfoBody = fmt.Sprintf(
			`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0">`+
				`<mcptt-Params>`+
				`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
				`<mcptt-calling-user-id><mcpttURI>%s</mcpttURI></mcptt-calling-user-id>`+
				`<session-type>%s</session-type>`+
				`<mcptt-calling-group-id><mcpttURI>%s</mcpttURI></mcptt-calling-group-id>`+
				`</mcptt-Params>`+
				`</mcpttinfo>`,
			groupURI, callerURI, sessionType, groupURI,
		)
	}

	const boundary = "mcxasboundary"
	multipartBody := fmt.Sprintf(
		"--%s\r\nContent-Type: application/sdp\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n%s\r\n"+
			"--%s--\r\n",
		boundary, sdpBody,
		boundary, mcpttInfoBody,
		boundary,
	)

	transport := strings.ToLower(strings.TrimSpace(reg.Transport))
	if transport == "" {
		transport = "udp"
	}
	// Route through the S-CSCF that delivered the REGISTER (SourceIP:SourcePort).
	target := ""
	if reg.SourceIP != "" {
		port := reg.SourcePort
		if port == 0 {
			port = 5060
		}
		target = net.JoinHostPort(reg.SourceIP, strconv.Itoa(port))
	}
	if target == "" {
		slog.Warn("RX INVITE: no route to member", "member", memberImpu)
		if done != nil {
			done <- false
		}
		return ""
	}

	// Route the terminating INVITE through S-CSCF's standard MT path per
	// 3GPP TS 24.229 §5.7.1.6. Target is the S-CSCF address from the
	// 3rd-party REGISTER (reg.SourceIP). No Route headers: S-CSCF performs
	// registration binding lookup and routes to P-CSCF → UE.
	var inviteRoutes []string

	// PAI must be the floor holder (TX UE), not the AS, so the MCPTT client can
	// identify who is speaking and trigger auto-answer for a group call.
	pai := initiatorURI
	if pai == "" {
		pai = s.cfg.MCX.SIPIdentity
	}
	branch := rfc3261BranchCookie + newToken()
	// Contact per TS 24.379 clause 6.3.2.2.3 item 4: the MCPTT and ICSI
	// feature tags, isfocus, and the session identity mapped from the group
	// session's own identity.
	sessionURI := s.advertisedSIPURI(transport)
	if v, ok := s.sessionIdentities.Load(txCallID); ok {
		sessionURI = v.(string)
	}
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(transport), advertiseHost(s.cfg), branch)},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, localTag)},
		{"To", fmt.Sprintf("<%s>", memberImpu)},
		{"Call-ID", callID},
		{"CSeq", "1 INVITE"},
		{"Contact", fmt.Sprintf("<%s>;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mcptt\";isfocus", sessionURI)},
		{"P-Asserted-Identity", fmt.Sprintf("<%s>", pai)},
		// Session timer offered per clause 6.3.2.2.3 items 2-3 and 5-6; the
		// refresher parameter is recommended omitted on this leg.
		{"Session-Expires", "1800"},
		{"Supported", "timer, tdialog, norefersub"},
		{"Content-Type", fmt.Sprintf(`multipart/mixed;boundary="%s"`, boundary)},
	}
	// Commencement mode from the member's own published Answer-Mode
	// Indication (clause 10.1.1.3.2 steps 7-8): "Manual" is mandatory when
	// the indication says manual (clause 6.3.2.2.6.2 step 5); "Auto" is
	// local policy for the automatic case (clause 6.3.2.2.5.2 step 8A), and
	// this server's policy is to assert it so the client commences without
	// user interaction, which is what its own setting asked for.
	if sessionType == "first-to-answer" {
		// Clause 11.1.1.4.1 step 3: a first-to-answer leg carries
		// Priv-Answer-Mode: Manual (RFC 5373) - the callee must answer
		// deliberately for the race to mean anything.
		hdrs = append(hdrs, header{"Priv-Answer-Mode", "Manual"})
	} else {
		switch mode {
		case answerModeAutomatic:
			hdrs = append(hdrs, header{"Answer-Mode", "Auto"})
		case answerModeManual:
			hdrs = append(hdrs, header{"Answer-Mode", "Manual"})
		}
	}
	// Clause 6.3.3.1.19: requests generated while the group is in an
	// in-progress emergency or imminent peril state carry the corresponding
	// Resource-Priority value.
	if rp := s.resourcePriorityFor(groupURI); rp != "" {
		hdrs = append(hdrs, header{"Resource-Priority", rp})
	}
	for i := len(inviteRoutes) - 1; i >= 0; i-- {
		hdrs = append([]header{{"Route", inviteRoutes[i]}}, hdrs...)
	}
	inviteMsg := buildRequest("INVITE", memberImpu, hdrs, []byte(multipartBody))

	// Registered before the send so a first-to-answer loser can be cancelled
	// while it is still ringing (clause 11.1.1.4.2 step 8 b).
	s.rxLegCancel.Store(callID, &rxCancelState{
		branch:     branch,
		target:     target,
		transport:  transport,
		requestURI: memberImpu,
		fromHeader: fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, localTag),
		toHeader:   fmt.Sprintf("<%s>", memberImpu),
		callID:     callID,
	})

	slog.Info("RX INVITE sending", "call_id", callID, "member", memberImpu, "target", target, "group_uri", groupURI, "tx_call_id", txCallID)
	// Transacted send: Timer A retransmission over UDP, Timer B timeout, and
	// the transaction layer ACKs a non-2xx final (RFC 3261 17.1.1.3). The
	// 200 OK is consumed below via pendingInvites, which predates the
	// transaction layer and still owns dialog-level handling.
	s.sendTransacted(ctx, transport, target, branch, "INVITE", []byte(inviteMsg))

	// The INVITE is on the wire; everything from here on depends only on the
	// member's response and runs detached so the caller can proceed to answer
	// the originator (TS 24.379 clause 10.1.1.4.2 step 14 g v orders member
	// invitations before the originating leg's final response).
	answerTimeout := 5 * time.Second
	if done != nil {
		// A private callee may answer manually; allow a ringing interval
		// instead of the group flow's short window.
		answerTimeout = 30 * time.Second
	}
	go s.completeRXLeg(ctx, ch, rxLegContext{
		callID: callID, txCallID: txCallID, groupURI: groupURI,
		initiatorURI: initiatorURI, memberImpu: memberImpu, localTag: localTag,
		target: target, transport: transport,
		audioPort: audioPort, rtcpPort: rtcpPort, sdpBody: sdpBody,
		done: done, answerTimeout: answerTimeout,
	})
	return callID
}

// rxLegContext carries what the asynchronous half of an RX leg needs from the
// synchronous build.
type rxLegContext struct {
	callID, txCallID, groupURI  string
	initiatorURI, memberImpu    string
	localTag, target, transport string
	audioPort, rtcpPort         int
	sdpBody                     string
	// done, when non-nil, receives whether the leg was established.
	done          chan bool
	answerTimeout time.Duration
}

func (s *Server) completeRXLeg(ctx context.Context, ch chan *Message, leg rxLegContext) {
	callID, txCallID, groupURI := leg.callID, leg.txCallID, leg.groupURI
	initiatorURI, memberImpu := leg.initiatorURI, leg.memberImpu
	localTag, target, transport := leg.localTag, leg.target, leg.transport
	audioPort, rtcpPort, sdpBody := leg.audioPort, leg.rtcpPort, leg.sdpBody
	_ = initiatorURI
	defer s.pendingInvites.Delete(callID)
	defer s.rxLegCancel.Delete(callID)
	established := false
	if leg.done != nil {
		defer func() {
			select {
			case leg.done <- established:
			default:
			}
		}()
	}
	answerTimeout := leg.answerTimeout
	if answerTimeout <= 0 {
		answerTimeout = 5 * time.Second
	}
	timer := time.NewTimer(answerTimeout)
	defer timer.Stop()
	var resp *Message
	select {
	case resp = <-ch:
	case <-timer.C:
		slog.Warn("RX INVITE timeout", "call_id", callID, "member", memberImpu)
		return
	case <-ctx.Done():
		return
	}

	fields := strings.Fields(resp.StartLine)
	if len(fields) < 2 {
		return
	}
	code, _ := strconv.Atoi(fields[1])
	if code < 200 || code >= 300 {
		slog.Warn("RX INVITE rejected", "call_id", callID, "member", memberImpu, "code", code)
		return
	}

	// Parse the RX UE's SDP answer to get its audio IP:port for relay targeting.
	sdpAnswer := ""
	ct := strings.ToLower(resp.Header("Content-Type"))
	if strings.Contains(ct, "application/sdp") {
		sdpAnswer = string(resp.Body)
	} else if part := resp.Part("application/sdp"); part != nil {
		sdpAnswer = string(part.Body)
	}
	rxSDP := parseSDP(sdpAnswer)
	remoteTag := tagFrom(resp.Header("To"))
	remoteContact := uriFromHeader(resp.Header("Contact"))

	// Build UAC route set: Record-Route from 200 OK reversed (RFC 3261 §12.1.2).
	recordRoutes := resp.HeadersFor("Record-Route")
	routeSet := make([]string, len(recordRoutes))
	for i, rr := range recordRoutes {
		routeSet[len(recordRoutes)-1-i] = rr
	}

	// ACK Request-URI is the remote Contact (or fall back to To URI).
	ackReqURI := memberImpu
	if remoteContact != "" {
		ackReqURI = remoteContact
	}

	// ACK target: first Route entry when lr routes present, otherwise Contact,
	// otherwise S-CSCF (the original target).
	ackTarget := target
	if len(routeSet) > 0 {
		if addr := addrFromSIPURI(routeSet[0]); addr != "" {
			ackTarget = addr
		}
	} else if remoteContact != "" {
		if addr := addrFromSIPURI(remoteContact); addr != "" {
			ackTarget = addr
		}
	}

	ackHdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s", strings.ToUpper(transport), advertiseHost(s.cfg), newToken())},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, localTag)},
		{"To", fmt.Sprintf("<%s>;tag=%s", memberImpu, remoteTag)},
		{"Call-ID", callID},
		{"CSeq", "1 ACK"},
		{"Contact", fmt.Sprintf("<%s>", s.advertisedSIPURI(transport))},
		{"User-Agent", productName},
	}
	for _, r := range routeSet {
		ackHdrs = append(ackHdrs, header{"Route", r})
	}
	ackMsg := buildRequest("ACK", ackReqURI, ackHdrs, nil)
	if err := s.sendOutbound(ctx, transport, ackTarget, []byte(ackMsg)); err != nil {
		slog.Warn("RX ACK send failed", "call_id", callID, "member", memberImpu, "err", err)
	}

	// Store the RX leg so Phase 1 relay can find it by GroupURI.
	now := time.Now().UTC()
	if _, err := s.st.UpsertCall(ctx, store.MCPTTCall{
		CallID:        callID,
		State:         "established",
		InitiatorURI:  s.cfg.MCX.SIPIdentity,
		TargetURI:     memberImpu,
		GroupURI:      groupURI,
		MCPTTID:       groupURI,
		RemoteTarget:  remoteContact,
		RouteSet:      strings.Join(routeSet, "\n"),
		LocalTag:      localTag,
		RemoteTag:     remoteTag,
		Transport:     transport,
		SourceAddr:    target,
		AudioIP:       rxSDP.Audio.ConnectionIP,
		AudioPort:     rxSDP.Audio.Port,
		AudioProto:    rxSDP.Audio.Proto,
		AudioPayloads: rxSDP.Audio.Payloads,
		// The member's negotiated floor control address, so the floor control
		// server can address Floor Taken / Floor Idle / Floor Release Multi
		// Talker messages to this leg (TS 24.380 clauses 6.3.4.4.2, 8.2.14).
		FloorControlIP:       rxSDP.FloorControl.ConnectionIP,
		FloorControlPort:     rxSDP.FloorControl.Port,
		FloorControlProto:    rxSDP.FloorControl.Proto,
		FloorControlPayloads: rxSDP.FloorControl.Payloads,
		LocalAudioPort:       audioPort,
		LocalRTCPPort:        rtcpPort,
		SDPOffer:             sdpBody,
		SDPAnswer:            sdpAnswer,
		AnsweredAt:           now,
		EstablishedAt:        now,
	}); err != nil {
		slog.Warn("RX call store failed", "call_id", callID, "member", memberImpu, "err", err)
		return
	}
	s.markSessionAnswered(ctx, callID)
	established = true
	s.NotifyConferenceChange(groupURI)
	slog.Info("RX INVITE established", "call_id", callID, "member", memberImpu,
		"audio_remote", fmt.Sprintf("%s:%d", rxSDP.Audio.ConnectionIP, rxSDP.Audio.Port),
		"group_uri", groupURI, "tx_call_id", txCallID)
}

// terminateRXLegs sends BYE to all AS-initiated RX legs for a group call when
// the TX call ends.
func (s *Server) terminateRXLegs(ctx context.Context, groupURI, txCallID string) {
	peers, err := s.st.ListCallsByGroup(ctx, groupURI)
	if err != nil {
		slog.Warn("RX teardown: lookup failed", "err", err, "group_uri", groupURI)
		return
	}
	for _, peer := range peers {
		if peer.CallID == txCallID {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(peer.InitiatorURI), strings.TrimSpace(s.cfg.MCX.SIPIdentity)) {
			continue
		}
		go s.sendRXBYE(context.Background(), peer)
	}
}

func (s *Server) sendRXBYE(ctx context.Context, call store.MCPTTCall) {
	s.sendRXBYEWithReason(ctx, call, "")
}

// sendRXBYEWithReason releases an AS-initiated leg; a non-empty reason is
// carried as the <release-reason> of an mcptt-info body (TS 24.379 clause
// 11.1.1.4.2 step 8 a: "not selected for call" for first-to-answer losers).
func (s *Server) sendRXBYEWithReason(ctx context.Context, call store.MCPTTCall, reason string) {
	transport := call.Transport
	if transport == "" {
		transport = "udp"
	}
	// Use Route set (reversed from 200 OK Record-Route) to route BYE through IMS core.
	byeRouteSet := strings.Fields(strings.ReplaceAll(call.RouteSet, "\n", " "))
	// Re-split on newlines properly
	if call.RouteSet != "" {
		byeRouteSet = strings.Split(call.RouteSet, "\n")
	}
	target := call.SourceAddr
	if len(byeRouteSet) > 0 {
		if addr := addrFromSIPURI(byeRouteSet[0]); addr != "" {
			target = addr
		}
	} else if call.RemoteTarget != "" {
		if addr := addrFromSIPURI(call.RemoteTarget); addr != "" {
			target = addr
		}
	}
	byeReqURI := call.TargetURI
	if call.RemoteTarget != "" {
		byeReqURI = call.RemoteTarget
	}
	branch := rfc3261BranchCookie + newToken()
	hdrs := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(transport), advertiseHost(s.cfg), branch)},
		{"Max-Forwards", "70"},
		{"From", fmt.Sprintf("<%s>;tag=%s", call.InitiatorURI, call.LocalTag)},
		{"To", fmt.Sprintf("<%s>;tag=%s", call.TargetURI, call.RemoteTag)},
		{"Call-ID", call.CallID},
		{"CSeq", "2 BYE"},
		{"User-Agent", productName},
	}
	for _, r := range byeRouteSet {
		if strings.TrimSpace(r) != "" {
			hdrs = append(hdrs, header{"Route", r})
		}
	}
	var body []byte
	if reason != "" {
		body = []byte(fmt.Sprintf(
			`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
				`<release-reason>%s</release-reason>`+
				`</mcptt-Params></mcpttinfo>`, reason))
		hdrs = append(hdrs, header{"Content-Type", "application/vnd.3gpp.mcptt-info+xml"})
	}
	bye := buildRequest("BYE", byeReqURI, hdrs, body)
	slog.Info("RX BYE sending", "call_id", call.CallID, "member", call.TargetURI, "group_uri", call.GroupURI, "reason", reason)
	s.sendTransacted(ctx, transport, target, branch, "BYE", []byte(bye))
	if err := s.st.UpdateCallState(ctx, call.CallID, "terminated"); err != nil {
		slog.Warn("RX BYE state update failed", "call_id", call.CallID, "err", err)
	}
}

func (s *Server) sendNotify(ctx context.Context, sub store.Subscription, subscribe *Message, send responder) error {
	target, transport, routes, err := learnedTarget(sub)
	if err != nil {
		return err
	}
	routes = s.notifyDialogRoutes(routes)
	if len(routes) > 0 {
		if routeTarget := addrFromSIPURI(routes[0]); routeTarget != "" {
			target = routeTarget
		}
	}

	body, contentType := s.notifyBody(ctx, sub)
	to := addTag(subscribe.Header("From"), sub.RemoteTag)
	from := addTag(subscribe.Header("To"), sub.LocalTag)
	if from == "" {
		from = fmt.Sprintf("<%s>;tag=%s", s.cfg.MCX.SIPIdentity, sub.LocalTag)
	}
	reqURI := notifyRequestURI(sub, routes, s.cfg.IMS.Realm)
	if routeListHasSyntheticTerm(routes) {
		slog.Error("synthetic term@pcscf route attempted for in-dialog NOTIFY", "call_id", sub.CallID, "event", sub.Event, "request_uri", reqURI, "routes", strings.Join(routes, ","))
		return fmt.Errorf("synthetic term@pcscf route rejected for in-dialog NOTIFY call_id=%s", sub.CallID)
	}
	// RFC 3261 §20.16: CSeq must be monotonically increasing within a dialog.
	var cseq uint32 = 1
	if prev, ok := s.notifyCSeq.Load(sub.CallID); ok {
		cseq = prev.(uint32) + 1
	}
	s.notifyCSeq.Store(sub.CallID, cseq)

	logNotifyDialogRoute(sub, reqURI, target, transport, s.notifyRouteSetOrder(), routes)
	branch := rfc3261BranchCookie + newToken()
	headers := []header{
		{"Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(transport), advertiseHost(s.cfg), branch)},
		{"Max-Forwards", "70"},
		{"From", from},
		{"To", to},
		{"Call-ID", sub.CallID},
		{"CSeq", fmt.Sprintf("%d NOTIFY", cseq)},
		{"Contact", fmt.Sprintf("<%s>", s.cfg.MCX.SIPIdentity)},
		{"User-Agent", productName},
		{"Event", sub.Event},
		{"Subscription-State", "active;expires=3600"},
		{"Content-Type", contentType},
	}
	for i := len(routes) - 1; i >= 0; i-- {
		headers = append([]header{{"Route", routes[i]}}, headers...)
	}
	msg := buildRequest("NOTIFY", reqURI, headers, body)
	// Transacted: the transaction layer owns retransmission and timeout, so
	// there is no synchronous send error to surface here.
	s.sendTransacted(ctx, transport, target, branch, "NOTIFY", []byte(msg))
	slog.Info("SIP NOTIFY sent", "target", target, "transport", transport, "request_uri", reqURI, "route_count", len(routes), "remote_target", sub.RemoteTarget, "call_id", sub.CallID, "event", sub.Event)
	slog.Debug("SIP NOTIFY request", "call_id", sub.CallID, "event", sub.Event, "target", target, "message", msg)
	return nil
}

func (s *Server) notifyDialogRoutes(routes []string) []string {
	if len(routes) == 0 {
		return routes
	}
	out := append([]string(nil), routes...)
	if s.notifyRouteSetOrder() == "reverse" {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}

func (s *Server) notifyRouteSetOrder() string {
	// RFC 3261 §12.2.1.1: the UAC uses the route set in the order stored (i.e.
	// as the Record-Routes appeared in the SUBSCRIBE). Default is "preserve"
	// (no reversal) so the NOTIFY follows the IMS-standard path
	// AS → S-CSCF → P-CSCF → UE, putting P-CSCF as the final hop where it can
	// deliver to the UE's registered transport (TCP or UDP).
	// "reverse" is kept as an override for non-standard deployments only.
	order := strings.ToLower(strings.TrimSpace(s.cfg.SIP.NotifyRouteSetOrder))
	if order == "reverse" {
		return "reverse"
	}
	return "preserve"
}

func routeListHasSyntheticTerm(routes []string) bool {
	for _, route := range routes {
		if strings.Contains(strings.ToLower(route), "sip:term@pcscf.") {
			return true
		}
	}
	return false
}

func logNotifyDialogRoute(sub store.Subscription, reqURI, target, transport, order string, routes []string) {
	attrs := []any{
		"event", sub.Event,
		"call_id", sub.CallID,
		"request_uri", reqURI,
		"route_set_order", order,
		"route_count", len(routes),
		"target_ip", target,
		"target_transport", transport,
	}
	for i, route := range routes {
		attrs = append(attrs, fmt.Sprintf("route_%d", i), route)
	}
	slog.Info("SIP NOTIFY dialog route selected", attrs...)
}

func notifyRequestURI(sub store.Subscription, routes []string, realm string) string {
	if remoteTarget := strings.TrimSpace(sub.RemoteTarget); remoteTarget != "" {
		return remoteTarget
	}
	return subscriberRequestURI(sub.SubscriberURI, realm)
}

func (s *Server) notifyBody(ctx context.Context, sub store.Subscription) ([]byte, string) {
	if strings.EqualFold(sub.Event, "conference") {
		groupURI := ""
		if len(sub.Selectors) > 0 {
			groupURI = sub.Selectors[0]
		}
		return s.conferenceNotifyBody(ctx, sub, groupURI, int(s.confVersion.Add(1)))
	}
	if strings.EqualFold(sub.Event, "xcap-diff") {
		body := s.xcapDiffBody(ctx, sub.SubscriberURI, sub.Selectors)
		slog.Debug("SIP xcap-diff NOTIFY body generated", "call_id", sub.CallID, "subscriber", sub.SubscriberURI, "body", body)
		return []byte(body), "application/xcap-diff+xml"
	}
	mcpttID := sub.SubscriberURI
	expires := time.Now().UTC().Add(time.Hour)
	return []byte(s.presenceBodyForAffiliations(mcpttID, s.affiliationNotifyEntries(ctx, mcpttID, expires), expires)), "application/pidf+xml"
}

func (s *Server) xcapDiffBody(ctx context.Context, subscriberURI string, requestedSelectors []string) string {
	ueID := "mcptt_UE_id"
	userProfile := strings.TrimSpace(subscriberURI)
	if userProfile == "" {
		userProfile = "default"
	}
	xcapRoot := strings.TrimSpace(s.cfg.CMS.XCAPRoot)
	if xcapRoot == "" {
		xcapRoot = xcapRootFromConfig(s.cfg)
	}
	selectors := normalizeXCAPSelectors(requestedSelectors)
	if len(selectors) == 0 {
		selectors = []string{
			"org.3gpp.mcptt.ue-config/users/" + ueID + "/" + ueID,
			"org.3gpp.mcptt.user-profile/users/" + userProfile + "/mcptt-user-profile",
			"org.3gpp.mcptt.service-config/global/service-config.xml",
		}
		selectors = append(selectors, s.gmsGroupSelectors(ctx, subscriberURI)...)
	}
	var documents strings.Builder
	for _, selector := range selectors {
		tag := s.xcapDocumentETag(ctx, selector)
		slog.Info("xcap_diff_notify",
			"subscription_type", xcapSubscriptionType([]string{selector}),
			"subscriber", subscriberURI,
			"selector", selector,
			"current_etag", tag,
			"included", true,
			"reason", "initial",
		)
		fmt.Fprintf(&documents, "\n  <document sel=\"%s\" new-etag=\"%s\"/>", xmlEscape(selector), xmlEscape(strings.Trim(tag, `"`)))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<xcap-diff xmlns="urn:ietf:params:xml:ns:xcap-diff" xcap-root="%s">
%s
</xcap-diff>`,
		xmlEscape(strings.TrimRight(xcapRoot, "/")),
		documents.String(),
	)
}

func (s *Server) xcapDocumentETag(ctx context.Context, selector string) string {
	path := "/" + strings.TrimPrefix(strings.TrimSpace(selector), "/")
	if s.st == nil {
		return cms.ContentETag(path)
	}
	if s.st != nil {
		if doc, err := s.st.GetCMSDocumentByPath(ctx, path); err == nil && doc != nil {
			return cms.ContentETag(doc.Body)
		}
	}
	return cms.ContentETag(cms.NewServer(s.cfg, s.st).DefaultDocument(ctx, path))
}

func (s *Server) gmsGroupSelectors(ctx context.Context, subscriberURI string) []string {
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return nil
	}
	userID := ""
	for _, user := range users {
		if strings.EqualFold(strings.TrimSpace(user.IMPU), strings.TrimSpace(subscriberURI)) ||
			strings.EqualFold(strings.TrimSpace(user.MCPTTID), strings.TrimSpace(subscriberURI)) {
			userID = user.ID
			break
		}
	}
	if userID == "" {
		return nil
	}
	memberships, err := s.st.ListGroupMemberships(ctx)
	if err != nil {
		return nil
	}
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		return nil
	}
	groupByID := map[string]store.Group{}
	for _, group := range groups {
		if group.Enabled && strings.TrimSpace(group.URI) != "" {
			groupByID[group.ID] = group
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, membership := range memberships {
		if membership.UserID != userID {
			continue
		}
		group := groupByID[membership.GroupID]
		if strings.TrimSpace(group.URI) == "" || seen[group.URI] {
			continue
		}
		seen[group.URI] = true
		out = append(out, "org.openmobilealliance.groups/global/byGroup/"+group.URI)
	}
	return out
}

func xcapResourceListSelectors(msg *Message) []string {
	var selectors []string
	for _, part := range msg.Parts() {
		if strings.Contains(strings.ToLower(part.Headers["Content-Type"]), "application/resource-lists+xml") {
			selectors = append(selectors, resourceListSelectors(part.Body)...)
		}
	}
	if len(selectors) == 0 && strings.Contains(strings.ToLower(msg.Header("Content-Type")), "application/resource-lists+xml") {
		selectors = resourceListSelectors(msg.Body)
	}
	return normalizeXCAPSelectors(selectors)
}

func resourceListSelectors(body []byte) []string {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var selectors []string
	for {
		tok, err := dec.Token()
		if err != nil {
			if err != io.EOF {
				slog.Debug("resource-list selector parse failed", "err", err)
			}
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "entry" {
			continue
		}
		for _, attr := range start.Attr {
			if attr.Name.Local == "uri" {
				selectors = append(selectors, attr.Value)
				break
			}
		}
	}
	return selectors
}

func normalizeXCAPSelectors(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, selector := range in {
		selector = strings.TrimSpace(selector)
		selector = strings.TrimPrefix(selector, "/")
		selector = normalizeXCAPDocumentSelector(selector)
		if selector == "" || seen[selector] {
			continue
		}
		seen[selector] = true
		out = append(out, selector)
	}
	return out
}

func normalizeXCAPDocumentSelector(selector string) string {
	v := strings.TrimRight(strings.TrimSpace(selector), "/")
	if strings.HasPrefix(v, "org.3gpp.mcptt.ue-config/users/") {
		parts := strings.Split(v, "/")
		if len(parts) == 3 && parts[0] == "org.3gpp.mcptt.ue-config" && parts[1] == "users" {
			return v + "/" + parts[2]
		}
	}
	if strings.HasPrefix(v, "org.3gpp.mcptt.user-profile/users/") {
		parts := strings.Split(v, "/")
		if len(parts) == 3 && parts[0] == "org.3gpp.mcptt.user-profile" && parts[1] == "users" {
			return v + "/mcptt-user-profile"
		}
	}
	return v
}

func xcapSubscriptionType(selectors []string) string {
	for _, selector := range selectors {
		if strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(selector), "/"), "org.openmobilealliance.groups/") {
			return "gms"
		}
	}
	return "cms"
}

func (s *Server) affiliatedGroupURI(ctx context.Context, userURI string) string {
	entries := s.affiliationNotifyEntries(ctx, userURI, time.Now().UTC().Add(time.Hour))
	for _, entry := range entries {
		if strings.EqualFold(entry.Status, "affiliated") {
			return entry.GroupURI
		}
	}
	return ""
}

type affiliationNotifyEntry struct {
	GroupURI    string
	DisplayName string
	Status      string
	ExpiresAt   time.Time
}

func (s *Server) affiliationNotifyEntries(ctx context.Context, userURI string, fallbackExpires time.Time) []affiliationNotifyEntry {
	if s.st == nil {
		return nil
	}
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return nil
	}
	userID := ""
	for _, user := range users {
		if strings.EqualFold(strings.TrimSpace(user.IMPU), strings.TrimSpace(userURI)) ||
			strings.EqualFold(strings.TrimSpace(user.MCPTTID), strings.TrimSpace(userURI)) {
			userID = user.ID
			break
		}
	}
	if userID == "" {
		return nil
	}
	memberships, err := s.st.ListGroupMemberships(ctx)
	if err != nil {
		return nil
	}
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		return nil
	}
	affiliations, err := s.st.ListGroupAffiliations(ctx)
	if err != nil {
		return nil
	}
	groupByID := map[string]store.Group{}
	for _, group := range groups {
		if group.Enabled && strings.TrimSpace(group.URI) != "" {
			groupByID[group.ID] = group
		}
	}
	affiliationByGroup := map[string]store.GroupAffiliation{}
	now := time.Now().UTC()
	for _, affiliation := range affiliations {
		if affiliation.UserID != userID {
			continue
		}
		if !affiliation.ExpiresAt.IsZero() && !affiliation.ExpiresAt.After(now) {
			continue
		}
		affiliationByGroup[affiliation.GroupID] = affiliation
	}
	var out []affiliationNotifyEntry
	seen := map[string]bool{}
	for _, membership := range memberships {
		if membership.UserID != userID || seen[membership.GroupID] {
			continue
		}
		group := groupByID[membership.GroupID]
		if strings.TrimSpace(group.URI) == "" {
			continue
		}
		seen[membership.GroupID] = true
		// Membership implies affiliation for this client population: every
		// group a user belongs to is reported as affiliated unless an
		// explicit group_affiliations row overrides that state below.
		entry := affiliationNotifyEntry{
			GroupURI:    group.URI,
			DisplayName: strings.TrimSpace(group.DisplayName),
			Status:      "affiliated",
			ExpiresAt:   fallbackExpires,
		}
		if affiliation, ok := affiliationByGroup[membership.GroupID]; ok {
			entry.Status = normalizeAffiliationState(affiliation.State)
			if !affiliation.ExpiresAt.IsZero() {
				entry.ExpiresAt = affiliation.ExpiresAt
			}
		}
		if entry.Status == "" {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (s *Server) presenceBody(mcpttID, groupURI string, expires time.Time) string {
	var entries []affiliationNotifyEntry
	if strings.TrimSpace(groupURI) != "" {
		entries = append(entries, affiliationNotifyEntry{
			GroupURI:  groupURI,
			Status:    "affiliated",
			ExpiresAt: expires,
		})
	}
	return s.presenceBodyForAffiliations(mcpttID, entries, expires)
}

func (s *Server) presenceBodyForAffiliations(mcpttID string, entries []affiliationNotifyEntry, fallbackExpires time.Time) string {
	if strings.TrimSpace(mcpttID) == "" {
		mcpttID = s.cfg.MCX.SIPIdentity
	}
	var affiliations strings.Builder
	for _, entry := range entries {
		if strings.TrimSpace(entry.GroupURI) == "" {
			continue
		}
		expires := entry.ExpiresAt
		if expires.IsZero() {
			expires = fallbackExpires
		}
		displayName := ""
		if strings.TrimSpace(entry.DisplayName) != "" {
			displayName = fmt.Sprintf(` display-name="%s"`, xmlEscape(entry.DisplayName))
		}
		fmt.Fprintf(&affiliations, `<mcpttPI10:affiliation group="%s" status="%s" expires="%s"%s/>`,
			xmlEscape(entry.GroupURI),
			xmlEscape(normalizeAffiliationState(entry.Status)),
			xmlEscape(expires.Format("2006-01-02T15:04:05Z")),
			displayName,
		)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:mcpttPI10="urn:3gpp:ns:mcpttPresInfo:1.0" entity="%s"><tuple id="%s"><status><basic>open</basic>%s</status><contact priority="1.0">%s</contact><timestamp>%s</timestamp></tuple><mcpttPI10:p-id>%s</mcpttPI10:p-id></presence>`,
		xmlEscape(mcpttID),
		xmlEscape(mcpttID),
		affiliations.String(),
		xmlEscape(mcpttID),
		xmlEscape(time.Now().UTC().Format("2006-01-02T15:04:05Z")),
		xmlEscape(mcpttID+"-"+strconv.FormatInt(time.Now().Unix(), 10)),
	)
}

func (s *Server) sdpAnswer(msg *Message) ([]byte, string) {
	if len(msg.Body) == 0 {
		return nil, ""
	}
	ct := strings.ToLower(msg.Header("Content-Type"))
	if !strings.Contains(ct, "application/sdp") {
		if part := msg.Part("application/sdp"); part == nil {
			return nil, ""
		}
	}
	offer, _ := s.sdpOffer(msg)
	offerInfo := parseSDP(offer)
	host := strings.TrimSpace(s.cfg.Media.AdvertiseHost)
	if host == "" {
		host = s.cfg.SIP.AdvertiseHost
	}
	if host == "" {
		host = "127.0.0.1"
	}
	audioPort := s.cfg.Media.AudioPort
	if audioPort == 0 {
		audioPort = 40000
	}
	rtcpPort := s.cfg.Media.RTCPPort
	if rtcpPort == 0 {
		rtcpPort = audioPort + 1
	}
	floorPort := s.cfg.Media.FloorControlPort
	if floorPort == 0 {
		floorPort = 40002
	}
	direction := s.cfg.Media.Direction
	if direction == "" {
		direction = "sendrecv"
	}
	audioPayload := "0"
	if len(offerInfo.Audio.Payloads) > 0 {
		audioPayload = offerInfo.Audio.Payloads[0]
	}
	floorProto := "udp"
	if offerInfo.FloorControl.Proto != "" {
		floorProto = offerInfo.FloorControl.Proto
	}
	floorPayload := "MCPTT"
	if len(offerInfo.FloorControl.Payloads) > 0 {
		floorPayload = offerInfo.FloorControl.Payloads[0]
	}
	// TS 24.380 clause 6.4: the answer grants the floor implicitly only when the
	// offer requested it (mc_implicit_request) and the server is willing to
	// auto-grant. Previously mc_granted was emitted unconditionally, an MCOP
	// client accommodation that handed every caller the floor at answer time
	// regardless of what it asked for. When not granting, the floor-control
	// media line is still offered so the participant can request the floor over
	// the control channel.
	floorFmtp := fmt.Sprintf("a=fmtp:%s MCPTT mc_priority=0;mc_queueing\r\n", floorPayload)
	if s.cfg.Media.FloorAutoGrant && offerRequestsImplicitFloor(offerInfo) {
		floorFmtp = fmt.Sprintf("a=fmtp:%s MCPTT mc_priority=0;mc_granted;mc_implicit_request\r\n", floorPayload)
	}
	body := "v=0\r\n" +
		fmt.Sprintf("o=mcxas 0 0 IN IP4 %s\r\n", host) +
		"s=MCPTT\r\n" +
		fmt.Sprintf("c=IN IP4 %s\r\n", host) +
		"t=0 0\r\n" +
		fmt.Sprintf("m=audio %d RTP/AVP %s\r\n", audioPort, audioPayload) +
		fmt.Sprintf("a=rtcp:%d IN IP4 %s\r\n", rtcpPort, host) +
		fmt.Sprintf("a=%s\r\n", direction) +
		fmt.Sprintf("m=application %d %s %s\r\n", floorPort, floorProto, floorPayload) +
		floorFmtp
	return []byte(body), "application/sdp"
}

// offerRequestsImplicitFloor reports whether the SDP offer's floor-control
// media requested an implicit floor grant (TS 24.380 clause 6.4).
func offerRequestsImplicitFloor(offer sdpInfo) bool {
	for _, attr := range offer.FloorControl.Attributes {
		if strings.Contains(strings.ToLower(attr), "mc_implicit_request") {
			return true
		}
	}
	return false
}

func sdpGrantsImplicitFloor(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "mc_granted") && strings.Contains(lower, "mc_implicit_request")
}

func (s *Server) sdpOffer(msg *Message) (string, string) {
	if len(msg.Body) == 0 {
		return "", ""
	}
	ct := strings.ToLower(msg.Header("Content-Type"))
	if strings.Contains(ct, "application/sdp") {
		return string(msg.Body), "application/sdp"
	}
	if part := msg.Part("application/sdp"); part != nil {
		return string(part.Body), "application/sdp"
	}
	return "", ""
}

func groupURIFromInvite(msg *Message) string {
	ruri := strings.TrimSpace(msg.URI)
	lower := strings.ToLower(ruri)
	if strings.Contains(lower, "group") {
		return ruri
	}
	return ""
}

// admitGroupInvite applies TS 24.379 clause 10.1.1.4.2 step 14 to an
// originating leg: affiliation to the group first (step 14 a, clause 6.3.6,
// warning "120"), then authorisation to initiate (step 14 b, warning "119").
// Group membership stands in for the initiate authorisation of clause 6.3.5.4
// until group documents carry per-user authorisation rules.
func (s *Server) admitGroupInvite(ctx context.Context, initiatorURI, groupURI string) admissionVerdict {
	if strings.TrimSpace(groupURI) == "" || s.st == nil {
		return admissionVerdict{Admitted: true}
	}
	userID, groupID, ok := s.userGroupIDs(ctx, initiatorURI, groupURI)
	if !ok {
		return admissionVerdict{Status: 403, Reason: "Forbidden",
			Warning: "120 user is not affiliated to this group"}
	}
	member, err := s.st.IsGroupMember(ctx, userID, groupID)
	if err != nil {
		slog.Error("group INVITE membership lookup failed", "err", err, "user_id", userID, "group_id", groupID)
		return admissionVerdict{Status: 500, Reason: "Server Internal Error"}
	}
	affiliated, err := s.st.IsGroupAffiliated(ctx, userID, groupID)
	if err != nil {
		slog.Error("group INVITE affiliation lookup failed", "err", err, "user_id", userID, "group_id", groupID)
		return admissionVerdict{Status: 500, Reason: "Server Internal Error"}
	}
	if !affiliated {
		// TS 24.379 clause 10.1.2.4.1.1 step 6: on a chat group an
		// unaffiliated caller who is eligible for implicit affiliation
		// (clause 9.2.2.3.6 - stood in for by group membership) is
		// affiliated implicitly (clause 9.2.2.3.7) instead of refused.
		if group := s.groupByURI(ctx, groupURI); group != nil && group.ChatGroup && member {
			// Implicit affiliation respects the N2 limit (clause 10.1.2.4.1.1
			// step 6 via 9.2.2.3.7; refusal per warning "102").
			if s.affiliationCount(ctx, userID) >= s.maxAffiliationsN2() {
				return admissionVerdict{Status: 486, Reason: "Busy Here",
					Warning: "102 too many simultaneous affiliations"}
			}
			if _, err := s.st.CreateGroupAffiliation(ctx, store.GroupAffiliation{
				UserID: userID, GroupID: groupID, State: "affiliated", Source: "implicit",
			}); err != nil {
				slog.Warn("chat group implicit affiliation failed", "err", err, "user_id", userID, "group_id", groupID)
			} else {
				slog.Info("chat group implicit affiliation", "user", initiatorURI, "group", groupURI)
				affiliated = true
			}
		}
	}
	if !affiliated {
		return admissionVerdict{Status: 403, Reason: "Forbidden",
			Warning: "120 user is not affiliated to this group"}
	}
	if !member {
		return admissionVerdict{Status: 403, Reason: "Forbidden",
			Warning: "119 user is not authorised to initiate the group call"}
	}
	return admissionVerdict{Admitted: true}
}

// groupByURI returns the enabled group record for a URI, or nil.
func (s *Server) groupByURI(ctx context.Context, groupURI string) *store.Group {
	if s.st == nil {
		return nil
	}
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		return nil
	}
	for _, g := range groups {
		if g.Enabled && strings.EqualFold(strings.TrimSpace(g.URI), strings.TrimSpace(groupURI)) {
			group := g
			return &group
		}
	}
	return nil
}

type sdpInfo struct {
	SessionConnectionIP string
	SessionAttributes   []string
	Audio               sdpMedia
	FloorControl        sdpMedia
}

type sdpMedia struct {
	Type         string
	Port         int
	Proto        string
	Payloads     []string
	ConnectionIP string
	Attributes   []string
}

func parseSDP(raw string) sdpInfo {
	var out sdpInfo
	var current *sdpMedia
	media := []sdpMedia{}
	flush := func() {
		if current != nil {
			media = append(media, *current)
			current = nil
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || len(line) < 2 || line[1] != '=' {
			continue
		}
		prefix, value := line[:2], strings.TrimSpace(line[2:])
		switch prefix {
		case "c=":
			ip := sdpConnectionIP(value)
			if current != nil {
				current.ConnectionIP = ip
			} else {
				out.SessionConnectionIP = ip
			}
		case "a=":
			if current != nil {
				current.Attributes = append(current.Attributes, value)
			} else {
				out.SessionAttributes = append(out.SessionAttributes, value)
			}
		case "m=":
			flush()
			fields := strings.Fields(value)
			if len(fields) < 3 {
				continue
			}
			port, _ := strconv.Atoi(strings.Split(fields[1], "/")[0])
			current = &sdpMedia{
				Type:         strings.ToLower(fields[0]),
				Port:         port,
				Proto:        fields[2],
				ConnectionIP: out.SessionConnectionIP,
			}
			if len(fields) > 3 {
				current.Payloads = append([]string(nil), fields[3:]...)
			}
		}
	}
	flush()
	for _, m := range media {
		if m.ConnectionIP == "" {
			m.ConnectionIP = out.SessionConnectionIP
		}
		if out.Audio.Type == "" && m.Type == "audio" {
			out.Audio = m
			continue
		}
		if out.FloorControl.Type == "" && isFloorControlMedia(m) {
			out.FloorControl = m
		}
	}
	return out
}

func sdpConnectionIP(value string) string {
	fields := strings.Fields(value)
	if len(fields) >= 3 {
		return fields[2]
	}
	return ""
}

func isFloorControlMedia(m sdpMedia) bool {
	if m.Type == "application" {
		return true
	}
	if strings.Contains(strings.ToLower(m.Proto), "mcptt") {
		return true
	}
	for _, attr := range m.Attributes {
		lower := strings.ToLower(attr)
		if strings.Contains(lower, "floor") || strings.Contains(lower, "mcptt") {
			return true
		}
	}
	return false
}

func mediaLogValue(m sdpMedia) string {
	if m.Type == "" {
		return ""
	}
	return fmt.Sprintf("%s/%d/%s", m.ConnectionIP, m.Port, m.Proto)
}

func Parse(raw []byte) (*Message, error) {
	parts := bytes.SplitN(raw, []byte("\r\n\r\n"), 2)
	if len(parts) < 2 {
		parts = bytes.SplitN(raw, []byte("\n\n"), 2)
	}
	if len(parts) < 1 {
		return nil, fmt.Errorf("empty message")
	}
	sc := bufio.NewScanner(bytes.NewReader(parts[0]))
	if !sc.Scan() {
		return nil, fmt.Errorf("missing start line")
	}
	start := strings.TrimSpace(sc.Text())
	fields := strings.Fields(start)
	if len(fields) < 3 {
		return nil, fmt.Errorf("bad start line %q", start)
	}
	msg := &Message{StartLine: start, Method: fields[0], URI: fields[1], Version: fields[2], Headers: map[string][]string{}, Raw: raw}
	var last string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if last != "" {
				vals := msg.Headers[last]
				vals[len(vals)-1] += " " + strings.TrimSpace(line)
				msg.Headers[last] = vals
			}
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := canonical(strings.TrimSpace(line[:i]))
		msg.Headers[name] = append(msg.Headers[name], strings.TrimSpace(line[i+1:]))
		last = name
	}
	if len(parts) == 2 {
		msg.Body = parts[1]
		if cl, err := strconv.Atoi(strings.TrimSpace(msg.Header("Content-Length"))); err == nil && cl >= 0 && cl < len(msg.Body) {
			msg.Body = msg.Body[:cl]
		}
	}
	return msg, sc.Err()
}

func (m *Message) Parts() []Part {
	ct := m.Header("Content-Type")
	boundary := contentTypeParam(ct, "boundary")
	if boundary == "" || !strings.Contains(strings.ToLower(ct), "multipart/") {
		return nil
	}
	rawBoundary := []byte("--" + boundary)
	sections := bytes.Split(m.Body, rawBoundary)
	var parts []Part
	for _, section := range sections {
		// A part body is opaque octets and must not be trimmed. Only the
		// delimiters around it may be: RFC 2046 clause 5.1.1 puts a CRLF
		// before each boundary and after it, and marks the close
		// delimiter with a trailing "--". Trimming whitespace from the
		// section instead ate the last octet of any body that ended in
		// one, which for the binary MIKEY messages of TS 33.180 Annex E
		// is about one upload in forty.
		if bytes.HasPrefix(section, []byte("--")) {
			continue // close delimiter and any epilogue
		}
		section = bytes.TrimPrefix(section, []byte("\r\n"))
		section = bytes.TrimPrefix(section, []byte("\n"))
		if len(bytes.TrimSpace(section)) == 0 {
			continue // the preamble before the first boundary
		}
		// Exactly one line break, the one introducing the next boundary.
		if bytes.HasSuffix(section, []byte("\r\n")) {
			section = section[:len(section)-2]
		} else if bytes.HasSuffix(section, []byte("\n")) {
			section = section[:len(section)-1]
		}
		headBody := bytes.SplitN(section, []byte("\r\n\r\n"), 2)
		if len(headBody) != 2 {
			headBody = bytes.SplitN(section, []byte("\n\n"), 2)
		}
		if len(headBody) != 2 {
			continue
		}
		headers := map[string]string{}
		sc := bufio.NewScanner(bytes.NewReader(headBody[0]))
		for sc.Scan() {
			line := sc.Text()
			if i := strings.IndexByte(line, ':'); i > 0 {
				headers[canonical(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
			}
		}
		parts = append(parts, Part{Headers: headers, Body: headBody[1]})
	}
	return parts
}

func (m *Message) Part(contentType string) *Part {
	want := strings.ToLower(contentType)
	for _, part := range m.Parts() {
		if strings.Contains(strings.ToLower(part.Headers["Content-Type"]), want) {
			p := part
			return &p
		}
	}
	return nil
}

// Limits on messages read from a stream transport. Every one of these bounds a
// value the remote peer controls, so none of them may be used to size an
// allocation or to terminate a loop on their own.
const (
	// sipReaderBufferBytes sizes the bufio.Reader, and so also caps the length
	// of a single header line. It needs to comfortably hold a long Via or
	// Record-Route set.
	sipReaderBufferBytes = 16 << 10

	// maxSIPHeaderBytes bounds the whole header section. Without it a peer
	// that never sends the terminating blank line grows the buffer until the
	// process runs out of memory.
	maxSIPHeaderBytes = 64 << 10

	// maxSIPBodyBytes bounds the body. MCPTT bodies are multipart XML plus SDP
	// and are measured in kilobytes, so this is generous.
	maxSIPBodyBytes = 256 << 10
)

// defaultStreamReadTimeout bounds how long a stream connection may go without
// delivering a complete message. It is reset before each read, so a peer that
// is exchanging traffic is unaffected while a connection that is opened and
// then left silent is reclaimed.
const defaultStreamReadTimeout = 5 * time.Minute

// streamReadTimeout returns the per-server read deadline. It is a method rather
// than a package global so tests can shorten it on their own Server without a
// shared variable that a still-running handler goroutine could read while the
// test's cleanup restores it.
func (s *Server) streamReadTimeout() time.Duration {
	if s.streamReadTimeoutOverride > 0 {
		return s.streamReadTimeoutOverride
	}
	return defaultStreamReadTimeout
}

// readHeaderLine reads one CRLF-terminated header line.
//
// bufio.Reader.ReadString would grow without bound, so a peer could exhaust
// memory with a single very long line before any length check on the assembled
// header section could run. ReadSlice instead fails once the buffer is full,
// which turns that into a bounded error.
func readHeaderLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", fmt.Errorf("SIP header line exceeds %d bytes", r.Size())
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

func readSIPMessage(r *bufio.Reader) ([]byte, error) {
	var head bytes.Buffer
	for {
		line, err := readHeaderLine(r)
		if err != nil {
			return nil, err
		}
		if head.Len()+len(line) > maxSIPHeaderBytes {
			return nil, fmt.Errorf("SIP header section exceeds %d bytes", maxSIPHeaderBytes)
		}
		head.WriteString(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
	}

	headerBytes := head.Bytes()
	msg, err := Parse(headerBytes)
	if err != nil {
		return nil, err
	}
	cl := 0
	if v := strings.TrimSpace(msg.Header("Content-Length")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid Content-Length %q", v)
		}
		// Checked before the allocation below, not after: Content-Length is
		// whatever the peer claims, and a single datagram declaring a
		// multi-gigabyte body would otherwise be enough to exhaust memory.
		if n > maxSIPBodyBytes {
			return nil, fmt.Errorf("Content-Length %d exceeds the %d byte limit", n, maxSIPBodyBytes)
		}
		cl = n
	}
	body := make([]byte, cl)
	if cl > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
	}
	return append(headerBytes, body...), nil
}

func (m *Message) Header(name string) string {
	vals := m.Headers[canonical(name)]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (m *Message) HeadersFor(name string) []string {
	vals := m.Headers[canonical(name)]
	return append([]string(nil), vals...)
}

func contentTypeParam(contentType, key string) string {
	key = strings.ToLower(key)
	for _, part := range strings.Split(contentType, ";") {
		part = strings.TrimSpace(part)
		if i := strings.IndexByte(part, '='); i > 0 && strings.ToLower(strings.TrimSpace(part[:i])) == key {
			return strings.Trim(strings.TrimSpace(part[i+1:]), `"`)
		}
	}
	return ""
}

func mcpttIdentityFromBody(msg *Message) string {
	body := msg.Body
	if part := msg.Part("application/vnd.3gpp.mcptt-info+xml"); part != nil {
		body = part.Body
	}
	text := string(body)
	for _, parent := range []string{"mcptt-request-uri", "mcptt-client-id"} {
		parentBody := xmlElementBody(text, parent)
		for _, child := range []string{"mcpttURI", "mcpttString"} {
			if v := xmlElementText(parentBody, child); v != "" {
				return v
			}
		}
	}
	if v := xmlElementText(text, "mcpttURI"); v != "" {
		return v
	}
	if v := xmlElementText(text, "mcpttString"); v != "" && !looksLikeJWT(v) {
		return v
	}
	return ""
}

func xmlElementBody(text, name string) string {
	openPrefix := "<" + name
	if i := strings.Index(text, openPrefix); i >= 0 {
		openEnd := strings.Index(text[i:], ">")
		if openEnd < 0 {
			return ""
		}
		start := i + openEnd + 1
		closeTag := "</" + name + ">"
		if j := strings.Index(text[start:], closeTag); j >= 0 {
			return text[start : start+j]
		}
	}
	return ""
}

func xmlElementText(text, name string) string {
	return strings.TrimSpace(xmlElementBody(text, name))
}

func looksLikeJWT(v string) bool {
	parts := strings.Split(v, ".")
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

func affiliationFromPresenceBody(msg *Message) (string, string) {
	body := msg.Body
	if part := msg.Part("application/pidf+xml"); part != nil {
		body = part.Body
	}
	text := string(body)
	groupURI := attrFromElement(text, "affiliation", "group")
	state := attrFromElement(text, "affiliation", "status")
	if state == "" {
		state = attrFromElement(text, "affiliation", "state")
	}
	state = normalizeAffiliationState(state)
	return groupURI, state
}

func attrFromElement(text, element, attr string) string {
	search := element
	pos := 0
	for {
		i := strings.Index(text[pos:], search)
		if i < 0 {
			return ""
		}
		i += pos
		start := strings.LastIndex(text[:i], "<")
		endRel := strings.Index(text[i:], ">")
		if start < 0 || endRel < 0 {
			return ""
		}
		end := i + endRel
		tag := text[start:end]
		if strings.Contains(tag, element) {
			for _, quote := range []string{`"`, `'`} {
				needle := attr + "=" + quote
				if j := strings.Index(tag, needle); j >= 0 {
					j += len(needle)
					if k := strings.Index(tag[j:], quote); k >= 0 {
						return strings.TrimSpace(tag[j : j+k])
					}
				}
			}
		}
		pos = end + 1
	}
}

func normalizeAffiliationState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "affiliated":
		return "affiliated"
	case "affiliating":
		return "affiliating"
	case "deaffiliating":
		return "deaffiliating"
	case "deaffiliated", "not-affiliated", "not affiliated", "no affiliated", "noaffiliated", "none", "":
		return "noaffiliated"
	default:
		return "noaffiliated"
	}
}

// servedUserExists reports whether the URI resolves to a provisioned, enabled
// user of this participating function.
func (s *Server) servedUserExists(ctx context.Context, userURI string) bool {
	if s.st == nil {
		return true
	}
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return false
	}
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(user.IMPU), strings.TrimSpace(userURI)) ||
			strings.EqualFold(strings.TrimSpace(user.MCPTTID), strings.TrimSpace(userURI)) {
			return true
		}
	}
	return false
}

func (s *Server) userGroupIDs(ctx context.Context, userURI, groupURI string) (string, string, bool) {
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return "", "", false
	}
	userID := ""
	for _, user := range users {
		if strings.EqualFold(strings.TrimSpace(user.IMPU), strings.TrimSpace(userURI)) ||
			strings.EqualFold(strings.TrimSpace(user.MCPTTID), strings.TrimSpace(userURI)) {
			userID = user.ID
			break
		}
	}
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		return "", "", false
	}
	groupID := ""
	for _, group := range groups {
		if strings.EqualFold(strings.TrimSpace(group.URI), strings.TrimSpace(groupURI)) {
			groupID = group.ID
			break
		}
	}
	return userID, groupID, userID != "" && groupID != ""
}

func (s *Server) findGroupAffiliation(ctx context.Context, userID, groupID string) (*store.GroupAffiliation, error) {
	affiliations, err := s.st.ListGroupAffiliations(ctx)
	if err != nil {
		return nil, err
	}
	for _, affiliation := range affiliations {
		if affiliation.UserID == userID && affiliation.GroupID == groupID {
			return &affiliation, nil
		}
	}
	return nil, nil
}

func xmlEscape(v string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(v))
	return b.String()
}

type header struct {
	Name  string
	Value string
}

const allowValue = "INVITE, ACK, CANCEL, BYE, MESSAGE, OPTIONS, NOTIFY, PRACK, UPDATE, REFER, SUBSCRIBE, PUBLISH, REGISTER"

func optionsHeaders() []header {
	return []header{
		{"Allow", allowValue},
		{"Accept", "application/sdp, application/vnd.3gpp.mcptt-info+xml, application/poc-settings+xml"},
		{"Supported", "timer, path"},
	}
}

func (s *Server) respond(send responder, req *Message, code int, reason string, extra []header, body []byte) {
	s.respondTagged(send, req, code, reason, "", extra, body)
}

func (s *Server) respondTagged(send responder, req *Message, code int, reason, localTag string, extra []header, body []byte) {
	var headers []header
	for _, via := range req.HeadersFor("Via") {
		headers = append(headers, header{"Via", via})
	}
	headers = append(headers,
		header{"From", req.Header("From")},
		header{"To", ensureToTag(req.Header("To"), code, localTag)},
		header{"Call-ID", req.Header("Call-ID")},
		header{"CSeq", req.Header("CSeq")},
		header{"Server", productName},
	)
	headers = append(headers, extra...)
	resp := buildResponse(code, reason, headers, body)
	if err := send([]byte(resp)); err != nil {
		slog.Warn("SIP response send failed", "code", code, "err", err)
	}
}

func buildResponse(code int, reason string, headers []header, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", code, reason)
	for _, h := range headers {
		if strings.TrimSpace(h.Value) != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", h.Name, h.Value)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.Write(body)
	return b.String()
}

func buildRequest(method, uri string, headers []header, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, uri)
	for _, h := range headers {
		if strings.TrimSpace(h.Value) != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", h.Name, h.Value)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.Write(body)
	return b.String()
}

func canonical(name string) string {
	switch strings.ToLower(name) {
	case "i":
		return "Call-ID"
	case "f":
		return "From"
	case "t":
		return "To"
	case "v":
		return "Via"
	case "l":
		return "Content-Length"
	case "c":
		return "Content-Type"
	default:
		parts := strings.Split(name, "-")
		for i := range parts {
			if parts[i] == "" {
				continue
			}
			parts[i] = strings.ToUpper(parts[i][:1]) + strings.ToLower(parts[i][1:])
		}
		return strings.Join(parts, "-")
	}
}

func hostFromContactURI(contact string) string {
	uri := uriFromHeader(contact)
	at := strings.IndexByte(uri, '@')
	if at < 0 {
		return ""
	}
	hostPort := uri[at+1:]
	if i := strings.IndexAny(hostPort, ";?"); i >= 0 {
		hostPort = hostPort[:i]
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

func identityFrom(msg *Message) string {
	for _, name := range []string{"P-Asserted-Identity", "P-Preferred-Identity", "From"} {
		if v := strings.Trim(strings.TrimSpace(msg.Header(name)), "<>"); v != "" {
			if i := strings.IndexByte(v, ';'); i >= 0 {
				v = v[:i]
			}
			return strings.Trim(v, "<>")
		}
	}
	return ""
}

func identityFromHeader(h string) string {
	if strings.Contains(h, "<") {
		return uriFromHeader(h)
	}
	v := strings.Trim(strings.TrimSpace(h), "<>")
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.Trim(v, "<>")
}

func registerExpires(msg *Message) int {
	contact := msg.Header("Contact")
	if strings.TrimSpace(contact) != "" {
		for _, part := range strings.Split(contact, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "expires=") {
				if n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(part[8:]), `"`)); err == nil && n >= 0 {
					return n
				}
			}
		}
	}
	if v := strings.TrimSpace(msg.Header("Expires")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 3600
}

func registerResponseHeaders(contact string) []header {
	if strings.TrimSpace(contact) == "" {
		return nil
	}
	return []header{{"Contact", contact}}
}

func (s *Server) advertisedSIPURI(transport string) string {
	tp := strings.ToLower(strings.TrimSpace(transport))
	if tp == "" {
		tp = strings.ToLower(strings.TrimSpace(s.cfg.SIP.Transport))
	}
	if tp == "" {
		tp = "udp"
	}
	host := strings.TrimSpace(s.cfg.SIP.AdvertiseHost)
	if host == "" {
		host = advertiseHost(s.cfg)
	}
	port := s.cfg.SIP.AdvertisePort
	if port == 0 {
		port = 5060
	}
	return fmt.Sprintf("sip:%s:%d;transport=%s", host, port, tp)
}

// allocateSessionIdentity mints the MCPTT session identity for a group
// session (TS 24.379 clause 4.5): a SIP URI unique to the session, hosted at
// the controlling function, carried to the client in the Contact of the final
// response. It deliberately contains no MCPTT ID or group ID, which clause
// 4.5 forbids when sensitive-data protection applies. A GRUU per RFC 5627
// requires the IMS core's cooperation; until the AS sits behind one, the URI
// is self-allocated at the advertised host.
func (s *Server) allocateSessionIdentity(callID string) string {
	uri := fmt.Sprintf("sip:mcptt-session-%s@%s", newToken(), advertiseHostOnly(s.cfg))
	s.sessionIdentities.Store(callID, uri)
	return uri
}

// chatSessionIdentity returns the session identity of the ongoing chat group
// session, creating it for the first joiner (TS 24.379 clause 10.1.2.4.1.1
// step 11 a). Later joiners share the identity; it is released when the last
// participant leaves.
func (s *Server) chatSessionIdentity(groupURI, callID string) string {
	key := strings.ToLower(strings.TrimSpace(groupURI))
	fresh := fmt.Sprintf("sip:mcptt-session-%s@%s", newToken(), advertiseHostOnly(s.cfg))
	actual, _ := s.chatSessions.LoadOrStore(key, fresh)
	uri := actual.(string)
	s.sessionIdentities.Store(callID, uri)
	return uri
}

// releaseChatSessionIfEmpty drops the chat session identity once no active
// leg remains in the group, so the next call is a new session.
func (s *Server) releaseChatSessionIfEmpty(ctx context.Context, groupURI string) {
	if strings.TrimSpace(groupURI) == "" {
		return
	}
	peers, err := s.st.ListCallsByGroup(ctx, groupURI)
	if err != nil || len(peers) > 0 {
		return
	}
	s.chatSessions.Delete(strings.ToLower(strings.TrimSpace(groupURI)))
}

// chatMaxParticipantCount mirrors the <on-network-max-participant-count> the
// generated group document advertises (TS 24.481 clause 7.2.4.2).
const chatMaxParticipantCount = 200

func (s *Server) recordRouteURI(transport string) string {
	if !s.cfg.SIP.RecordRoute {
		return ""
	}
	return strings.TrimSuffix(s.advertisedSIPURI(transport), ">") + ";lr"
}

func inviteResponseHeaders(contactURI, recordRoute string, inbound []string, contentType string) []header {
	headers := recordRouteHeaders(recordRoute, inbound)
	headers = append(headers,
		header{"Contact", fmt.Sprintf("<%s>", contactURI)},
		header{"Allow", allowValue},
	)
	if contentType != "" {
		headers = append(headers, header{"Content-Type", contentType})
	}
	return headers
}

func recordRouteHeaders(recordRoute string, inbound []string) []header {
	var headers []header
	if strings.TrimSpace(recordRoute) != "" && !routeListContains(inbound, recordRoute) {
		headers = append(headers, header{"Record-Route", fmt.Sprintf("<%s>", recordRoute)})
	}
	for _, rr := range inbound {
		if strings.TrimSpace(rr) != "" {
			headers = append(headers, header{"Record-Route", rr})
		}
	}
	return headers
}

func routeSetWithAS(inbound, recordRoute string) string {
	lines := splitHeaderLines(inbound)
	if strings.TrimSpace(recordRoute) != "" && !routeListContains(lines, recordRoute) {
		lines = append([]string{fmt.Sprintf("<%s>", recordRoute)}, lines...)
	}
	return strings.Join(lines, "\n")
}

func splitHeaderLines(v string) []string {
	var out []string
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func routeListContains(routes []string, uri string) bool {
	uri = strings.Trim(strings.TrimSpace(uri), "<>")
	for _, route := range routes {
		if strings.EqualFold(strings.Trim(strings.TrimSpace(route), "<>"), uri) {
			return true
		}
	}
	return false
}

func splitAddr(addr string) (string, int) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(portText)
	return host, port
}

func imsiFromIdentity(identity string) string {
	identity = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(identity)), "sip:")
	if at := strings.IndexByte(identity, '@'); at > 0 {
		user := identity[:at]
		for _, r := range user {
			if r < '0' || r > '9' {
				return ""
			}
		}
		return user
	}
	return ""
}

func contactHasFeature(contact, feature string) bool {
	for _, tag := range contactFeatureTags(contact) {
		if strings.EqualFold(tag, feature) {
			return true
		}
	}
	return false
}

func contactFeatureTags(contact string) []string {
	var out []string
	for _, part := range strings.Split(contact, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "+") {
			if i := strings.IndexByte(part, '='); i >= 0 {
				out = append(out, part[:i])
			} else {
				out = append(out, part)
			}
		}
	}
	return out
}

func contactICSIRefs(contact string) []string {
	var out []string
	for _, part := range strings.Split(contact, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "+g.3gpp.icsi-ref=") {
			continue
		}
		v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(part, "+g.3gpp.icsi-ref=")), `"`)
		if decoded, err := url.QueryUnescape(v); err == nil {
			v = decoded
		}
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func tagFrom(header string) string {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "tag=") {
			return strings.TrimSpace(part[4:])
		}
	}
	return ""
}

func cseqNumber(cseq string) uint32 {
	fields := strings.Fields(cseq)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(fields[0], 10, 32)
	return uint32(n)
}

func addTag(h, tag string) string {
	h = strings.TrimSpace(h)
	if h == "" || tag == "" || tagFrom(h) != "" {
		return h
	}
	return h + ";tag=" + tag
}

func ensureToTag(h string, code int, localTag string) string {
	if code < 200 || tagFrom(h) != "" {
		return h
	}
	if localTag != "" {
		return addTag(h, localTag)
	}
	return addTag(h, newToken())
}

func newToken() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

func quote(s string) string { return `"` + s + `"` }

func sipETag() string {
	return "vc-" + newToken()
}

func subscriberRequestURI(uri, realm string) string {
	uri = strings.Trim(strings.TrimSpace(uri), "<>")
	if i := strings.IndexByte(uri, ';'); i >= 0 {
		uri = uri[:i]
	}
	if strings.HasPrefix(strings.ToLower(uri), "sip:") && strings.Contains(uri, "@") {
		user := strings.TrimPrefix(uri, "sip:")
		if at := strings.IndexByte(user, '@'); at > 0 {
			// RFC 3265 §3.2: Request-URI MUST match the Contact URI of the SUBSCRIBE.
			// No transport parameter — let the proxy resolve via registered contact.
			return "sip:" + user[:at] + "@" + realm
		}
	}
	return uri
}

func learnedTarget(sub store.Subscription) (target, transport string, routes []string, err error) {
	transport = strings.ToLower(strings.TrimSpace(sub.Transport))
	if transport == "" {
		transport = "udp"
	}
	for _, route := range strings.Split(sub.RouteSet, "\n") {
		route = strings.TrimSpace(route)
		if route != "" {
			routes = append(routes, route)
		}
	}
	if len(routes) > 0 {
		if target = addrFromSIPURI(routes[0]); target != "" {
			return target, transport, routes, nil
		}
	}
	if target = addrFromVia(sub.TopVia); target != "" {
		return target, transport, routes, nil
	}
	if strings.TrimSpace(sub.SourceAddr) != "" {
		return sub.SourceAddr, transport, routes, nil
	}
	return "", "", nil, fmt.Errorf("no learned SIP route for subscription call_id=%s", sub.CallID)
}

func (s *Server) sendOutbound(ctx context.Context, transport, target string, msg []byte) error {
	transport = strings.ToLower(strings.TrimSpace(transport))
	dialer := net.Dialer{}

	if transport == "tls" {
		clientConf, err := tlsutil.ClientConfig(s.cfg.TLS, "")
		if err != nil {
			return err
		}
		tlsDialer := tls.Dialer{NetDialer: &dialer, Config: clientConf}
		conn, err := tlsDialer.DialContext(ctx, "tcp", target)
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write(msg)
		return err
	}

	conn, err := dialer.DialContext(ctx, transport, target)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(msg)
	return err
}

func addrFromVia(via string) string {
	fields := strings.Fields(via)
	if len(fields) < 2 {
		return ""
	}
	return hostPort(fields[1])
}

func addrFromSIPURI(uri string) string {
	uri = strings.TrimSpace(uri)
	uri = strings.Trim(uri, "<>")
	if i := strings.IndexByte(uri, ';'); i >= 0 {
		uri = uri[:i]
	}
	if strings.HasPrefix(strings.ToLower(uri), "sip:") {
		uri = strings.TrimPrefix(uri, "sip:")
	}
	if at := strings.LastIndex(uri, "@"); at >= 0 {
		uri = uri[at+1:]
	}
	return hostPort(uri)
}

func hostPort(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "<>"))
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	host, port, err := net.SplitHostPort(v)
	if err == nil {
		if host == "" {
			host = "127.0.0.1"
		}
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(v, ":") && strings.Count(v, ":") == 1 {
		return v
	}
	return net.JoinHostPort(v, "5060")
}

func uriFromHeader(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.Index(h, "<"); i >= 0 {
		if j := strings.Index(h[i+1:], ">"); j >= 0 {
			return h[i+1 : i+1+j]
		}
	}
	if i := strings.IndexByte(h, ';'); i >= 0 {
		h = h[:i]
	}
	return strings.Trim(h, "<>")
}

// advertiseHostOnly is the bare advertised host, for header fields that want
// a hostname rather than a host:port (for example Warning, RFC 3261 20.43).
func advertiseHostOnly(cfg config.Config) string {
	host := strings.TrimSpace(cfg.SIP.AdvertiseHost)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1"
	}
	return host
}

func advertiseHost(cfg config.Config) string {
	host := strings.TrimSpace(cfg.SIP.AdvertiseHost)
	_, port, err := net.SplitHostPort(cfg.SIP.UDPListen)
	if err != nil || port == "" {
		port = "5060"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func xcapRootFromConfig(cfg config.Config) string {
	host := strings.TrimSpace(cfg.SIP.AdvertiseHost)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	_, port, err := net.SplitHostPort(cfg.CMS.Listen)
	if err != nil || port == "" {
		port = "8100"
	}
	return "http://" + net.JoinHostPort(host, port) + "/xcap-root"
}

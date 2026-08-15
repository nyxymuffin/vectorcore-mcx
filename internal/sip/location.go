package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Location procedures at the participating MCPTT function, TS 24.379 clause
// 13.2: location reports from clients are ingested and stored (13.2.4.1),
// authorised clients can request another user's location on demand
// (13.2.3.2, relayed to the target per 13.2.3.1 with the report forwarded
// back), and clients get a periodic-report configuration (13.2.2) when
// sip.location.report_interval_seconds is set.
//
// The location-info bodies follow the Annex F.3 schema: <Configuration>,
// <Request> and <Report> under the <location-info> root.

const ctLocationInfo = "application/vnd.3gpp.mcptt-location-info+xml"

func locationInfoOf(msg *Message) string {
	if part := msg.Part(ctLocationInfo); part != nil {
		return string(part.Body)
	}
	if strings.Contains(strings.ToLower(msg.Header("Content-Type")), "mcptt-location-info") {
		return string(msg.Body)
	}
	return ""
}

// handleLocationMessage dispatches a SIP MESSAGE carrying a location-info
// body: <Report> ingests, <Request> relays toward the target.
func (s *Server) handleLocationMessage(ctx context.Context, send responder, msg *Message, source string) {
	info := locationInfoOf(msg)
	originator := identityFrom(msg)

	switch {
	case strings.Contains(info, "<Report"):
		// Clause 13.2.4.1: the report is authorised on the served MCPTT ID.
		if !s.servedUserExists(ctx, originator) {
			s.respond(send, msg, 403, "Forbidden", nil, nil)
			return
		}
		if _, err := s.st.UpsertPublishedState(ctx, store.PublishedState{
			UserURI: originator,
			Event:   "location",
			Body:    info,
		}); err != nil {
			s.respond(send, msg, 500, "Server Internal Error", nil, nil)
			return
		}
		slog.Info("MCPTT location report stored", "user", originator, "source", source)
		s.respond(send, msg, 200, "OK", nil, nil)

		// A pending on-demand request for this user's location is answered by
		// forwarding the report (clause 13.2.3.2 last step / 13.2.4).
		if v, ok := s.locationRequests.LoadAndDelete(strings.ToLower(strings.TrimSpace(originator))); ok {
			requester := v.(string)
			body := fmt.Sprintf(
				`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
					`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
					`<mcptt-calling-user-id><mcpttURI>%s</mcpttURI></mcptt-calling-user-id>`+
					`</mcptt-Params></mcpttinfo>`, requester, originator)
			s.sendMcpttMessageWithParts(ctx, requester, []messagePart{
				{contentType: "application/vnd.3gpp.mcptt-info+xml", body: body},
				{contentType: ctLocationInfo, body: info},
			})
			slog.Info("MCPTT location report forwarded", "target", requester, "about", originator)
		}

	case strings.Contains(info, "<Request"):
		// Clause 13.2.3.2: an authorised client requests another user's
		// location; the participating function relays a 13.2.3.1 request
		// toward the target client. (Profile-based authorisation of the
		// requester is stood in for by the served-user check.)
		if !s.servedUserExists(ctx, originator) {
			s.respond(send, msg, 403, "Forbidden", nil, nil)
			return
		}
		target := strings.TrimSpace(mcpttIdentityFromBody(msg))
		if target == "" || !s.servedUserExists(ctx, target) {
			s.respond(send, msg, 404, "Not Found", nil, nil)
			return
		}
		s.locationRequests.Store(strings.ToLower(target), originator)
		reqBody := fmt.Sprintf(
			`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
				`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
				`</mcptt-Params></mcpttinfo>`, target)
		locBody := `<location-info xmlns="urn:3gpp:ns:mcpttLocationInfo:1.0"><Request/></location-info>`
		s.sendMcpttMessageWithParts(ctx, target, []messagePart{
			{contentType: "application/vnd.3gpp.mcptt-info+xml", body: reqBody},
			{contentType: ctLocationInfo, body: locBody},
		})
		slog.Info("MCPTT location request relayed", "requester", originator, "target", target)
		s.respond(send, msg, 200, "OK", nil, nil)

	default:
		s.respond(send, msg, 400, "Bad Request", nil, nil)
	}
}

// sendLocationReportingConfiguration sends the clause 13.2.2 configuration
// MESSAGE with a periodic-report trigger to a served client.
func (s *Server) sendLocationReportingConfiguration(ctx context.Context, targetImpu string) {
	interval := s.cfg.SIP.Location.ReportIntervalSeconds
	if interval <= 0 {
		return
	}
	info := fmt.Sprintf(
		`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
			`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
			`</mcptt-Params></mcpttinfo>`, targetImpu)
	config := fmt.Sprintf(
		`<location-info xmlns="urn:3gpp:ns:mcpttLocationInfo:1.0">`+
			`<Configuration>`+
			`<NonEmergencyLocationInformation><ServingEcgi/></NonEmergencyLocationInformation>`+
			`<TriggeringCriteria><PeriodicReport TriggerId="vectorcore-periodic">%d</PeriodicReport></TriggeringCriteria>`+
			`<MinimumIntervalLength>%d</MinimumIntervalLength>`+
			`</Configuration>`+
			`</location-info>`, interval, interval)
	s.sendMcpttMessageWithParts(ctx, targetImpu, []messagePart{
		{contentType: "application/vnd.3gpp.mcptt-info+xml", body: info},
		{contentType: ctLocationInfo, body: config},
	})
	slog.Info("MCPTT location reporting configured", "target", targetImpu, "interval_s", interval)
}

// messagePart is one MIME part of a notification MESSAGE.
type messagePart struct {
	contentType string
	body        string
}

// sendMcpttMessageWithParts is sendMcpttMessage with a multipart body.
func (s *Server) sendMcpttMessageWithParts(ctx context.Context, targetImpu string, parts []messagePart) {
	if len(parts) == 1 {
		s.sendMcpttMessage(ctx, targetImpu, parts[0].body)
		return
	}
	const boundary = "mcxasloc"
	var b strings.Builder
	for _, part := range parts {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s\r\n\r\n%s\r\n", boundary, part.contentType, part.body)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	s.sendMcpttMessageRaw(ctx, targetImpu, b.String(),
		fmt.Sprintf(`multipart/mixed;boundary="%s"`, boundary))
}

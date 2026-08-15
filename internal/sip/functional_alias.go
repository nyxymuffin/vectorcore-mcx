package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Functional alias status change at the participating function, TS 24.379
// clause 9A.2.2.2.3. The publication arrives as SIP PUBLISH with
// Event: presence and an application/pidf+xml body whose <tuple>/<status>
// carries <functionalAlias functionalAliasID="..."> elements (clause 9A.3.1)
// - the same event package affiliation uses, which is why the previous code
// silently swallowed FA activations as failed affiliation lookups. The
// <functionalAlias> element is the discriminator.

// faExpiresRequired is the Expires value an activation must carry
// (clause 9A.2.1.2 step 4 / 9A.2.2.2.3 step 5).
const faExpiresRequired = 4294967295

// pidfCarriesFunctionalAlias reports whether a pidf body is a functional
// alias publication rather than an affiliation one.
func pidfCarriesFunctionalAlias(msg *Message) bool {
	body := msg.Body
	if part := msg.Part("application/pidf+xml"); part != nil {
		body = part.Body
	}
	return strings.Contains(string(body), "<functionalAlias")
}

// functionalAliasesFromBody extracts the functionalAliasID attribute values
// of every <functionalAlias> element in the pidf body.
func functionalAliasesFromBody(msg *Message) []string {
	body := msg.Body
	if part := msg.Part("application/pidf+xml"); part != nil {
		body = part.Body
	}
	text := string(body)
	var aliases []string
	for {
		i := strings.Index(text, "<functionalAlias")
		if i < 0 {
			break
		}
		text = text[i:]
		end := strings.Index(text, ">")
		if end < 0 {
			break
		}
		tag := text[:end]
		if v := xmlAttr(tag, "functionalAliasID"); v != "" {
			aliases = append(aliases, v)
		}
		text = text[end:]
	}
	return aliases
}

// xmlAttr extracts a double-quoted attribute value from an element open tag.
func xmlAttr(tag, name string) string {
	i := strings.Index(tag, name+"=\"")
	if i < 0 {
		return ""
	}
	rest := tag[i+len(name)+2:]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

// handleFunctionalAliasPublish implements clause 9A.2.2.2.3 for the
// unprotected case (XML integrity/confidentiality protection is KMS scope,
// carried forward).
func (s *Server) handleFunctionalAliasPublish(ctx context.Context, send responder, msg *Message) {
	// Step 1: the served MCPTT ID from <mcptt-request-uri>.
	servedID := mcpttIdentityFromBody(msg)
	if servedID == "" {
		servedID = identityFrom(msg)
	}
	// Step 2: the originating identity from P-Asserted-Identity.
	originator := identityFrom(msg)

	// Step 4: the originator must be the served user (delegated modification
	// authority is not supported).
	if !strings.EqualFold(strings.TrimSpace(servedID), strings.TrimSpace(originator)) {
		slog.Warn("functional alias change for another user refused",
			"served", servedID, "originator", originator)
		s.respond(send, msg, 403, "Forbidden", nil, nil)
		return
	}

	aliases := functionalAliasesFromBody(msg)
	if len(aliases) == 0 {
		s.respond(send, msg, 400, "Bad Request", nil, nil)
		return
	}

	// Step 4A/4B: each alias must be in the user's FunctionalAliasList (the
	// user-profile stand-in on the provisioned user record).
	authorised := s.authorisedFunctionalAliases(ctx, servedID)
	for _, alias := range aliases {
		if !authorised[strings.ToLower(strings.TrimSpace(alias))] {
			slog.Warn("functional alias change not authorised",
				"mcptt_id", servedID, "alias", alias)
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("201 user not authorized to change the functional alias status")}, nil)
			return
		}
	}

	// Step 5: Expires must be 4294967295 (activate) or 0 (deactivate);
	// anything else - including absent - is 423 with Min-Expires.
	expiresRaw := strings.TrimSpace(msg.Header("Expires"))
	var status string
	var expiresAt time.Time
	switch expiresRaw {
	case fmt.Sprint(faExpiresRequired):
		status = "activated"
		// The candidate expiration interval (step 6) is the requested one;
		// this server does not shorten it, so no expiry timestamp is stored.
	case "0":
		status = "deactivated"
	default:
		s.respond(send, msg, 423, "Interval Too Brief",
			[]header{{"Min-Expires", fmt.Sprint(faExpiresRequired)}}, nil)
		return
	}

	pidfa := ""
	{
		body := msg.Body
		if part := msg.Part("application/pidf+xml"); part != nil {
			body = part.Body
		}
		pidfa = xmlElementText(string(body), "p-id-fa")
	}

	for _, alias := range aliases {
		if _, err := s.st.UpsertFunctionalAliasStatus(ctx, store.FunctionalAliasStatus{
			MCPTTID:   servedID,
			AliasURI:  alias,
			Status:    status,
			PIDFA:     pidfa,
			ExpiresAt: expiresAt,
		}); err != nil {
			slog.Error("functional alias store failed", "err", err, "mcptt_id", servedID, "alias", alias)
			s.respond(send, msg, 500, "Server Internal Error", nil, nil)
			return
		}
		slog.Info("functional alias status changed",
			"mcptt_id", servedID, "alias", alias, "status", status, "p_id_fa", pidfa)
	}

	s.respond(send, msg, 200, "OK", []header{
		{"SIP-ETag", sipETag()},
		{"Expires", expiresRaw},
	}, nil)
}

// authorisedFunctionalAliases returns the lowercase set of aliases the served
// user may activate, from the FunctionalAliasList stand-in on the user record
// (clause 9A.2.2.2.3 step 4A a).
func (s *Server) authorisedFunctionalAliases(ctx context.Context, mcpttID string) map[string]bool {
	out := map[string]bool{}
	if s.st == nil {
		return out
	}
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return out
	}
	for _, user := range users {
		if strings.EqualFold(strings.TrimSpace(user.IMPU), strings.TrimSpace(mcpttID)) ||
			strings.EqualFold(strings.TrimSpace(user.MCPTTID), strings.TrimSpace(mcpttID)) {
			for _, alias := range user.FunctionalAliases {
				out[strings.ToLower(strings.TrimSpace(alias))] = true
			}
			return out
		}
	}
	return out
}

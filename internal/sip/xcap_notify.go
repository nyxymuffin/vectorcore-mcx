package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Change-triggered xcap-diff notification (RFC 5875, TS 24.481 clause 6.3.13
// document subscriptions): when a document changes, subscribers with a
// matching selector get an in-dialog NOTIFY with the current xcap-diff state,
// not just the initial one their SUBSCRIBE produced.
//
// Active xcap-diff subscriptions are registered in memory when the SUBSCRIBE
// is accepted and dropped on unsubscribe; they are dialog state, so they do
// not survive a restart (the client re-subscribes).

// registerXCAPSubscription tracks or drops an xcap-diff subscription.
func (s *Server) registerXCAPSubscription(sub store.Subscription, expires int) {
	if !strings.EqualFold(sub.Event, "xcap-diff") || sub.CallID == "" {
		return
	}
	if expires == 0 {
		s.xcapSubs.Delete(sub.CallID)
		return
	}
	s.xcapSubs.Store(sub.CallID, sub)
}

// NotifyXCAPChange sends a change NOTIFY to every xcap-diff subscriber whose
// selectors touch the application usage of a changed document. Matching is at
// AUID granularity: over-notifying is harmless (the xcap-diff body carries
// the current entity tags, so an unaffected subscriber sees no difference),
// under-notifying would violate RFC 5875.
func (s *Server) NotifyXCAPChange(paths ...string) {
	changed := map[string]bool{}
	for _, p := range paths {
		if auid := xcapAUIDOf(p); auid != "" {
			changed[auid] = true
		}
	}
	if len(changed) == 0 {
		return
	}
	ctx := context.Background()
	s.xcapSubs.Range(func(_, v any) bool {
		sub := v.(store.Subscription)
		if !selectorsTouchAUIDs(sub.Selectors, changed) {
			return true
		}
		subscribe, err := synthesizeSubscribe(sub)
		if err != nil {
			slog.Warn("xcap change notify: synthesize failed", "call_id", sub.CallID, "err", err)
			return true
		}
		if err := s.sendNotify(ctx, sub, subscribe, nil); err != nil {
			slog.Warn("xcap change notify failed", "call_id", sub.CallID, "err", err)
		} else {
			slog.Info("xcap change notify sent", "call_id", sub.CallID,
				"subscriber", sub.SubscriberURI, "changed_auids", len(changed))
		}
		return true
	})
}

// xcapAUIDOf extracts the application usage id from an XCAP document path.
func xcapAUIDOf(path string) string {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if i := strings.IndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return path
}

func selectorsTouchAUIDs(selectors []string, changed map[string]bool) bool {
	if len(selectors) == 0 {
		// A selector-less subscription watches everything it can see.
		return true
	}
	for _, sel := range selectors {
		if changed[xcapAUIDOf(sel)] {
			return true
		}
	}
	return false
}

// synthesizeSubscribe reconstructs the dialog-defining headers of the
// original SUBSCRIBE from the stored subscription, so sendNotify builds the
// in-dialog NOTIFY exactly as it would inside the SUBSCRIBE transaction.
func synthesizeSubscribe(sub store.Subscription) (*Message, error) {
	raw := fmt.Sprintf(
		"SUBSCRIBE %s SIP/2.0\r\n"+
			"From: <%s>;tag=%s\r\n"+
			"To: <%s>;tag=%s\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: 1 SUBSCRIBE\r\n"+
			"Event: %s\r\n"+
			"Content-Length: 0\r\n\r\n",
		sub.TargetURI, sub.SubscriberURI, sub.RemoteTag,
		sub.TargetURI, sub.LocalTag, sub.CallID, sub.Event)
	return Parse([]byte(raw))
}

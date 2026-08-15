package sip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Group regroup using a preconfigured group, TS 24.379 clause 16.2: an
// authorised user asks the controlling function to fuse several groups into
// one temporary group identity (TGI). Calls then run on the TGI and reach the
// members of every constituent group, while calls to a constituent group
// itself are refused with warning "148 group is regrouped" (clause
// 10.1.1.4.2 / 10.1.2.4.1.1 step 4 c).
//
// The controlling function of a constituent group is the non-controlling
// function of the regroup (clause 16.2.4). Here every group is served
// in-process, so the per-constituent SIP MESSAGE fan-out of clause 16.2.3.1
// step 4 collapses into local bookkeeping; the client notifications of
// clause 16.2.2.4 are sent.

const ctRegroup = "application/vnd.3gpp.mcptt-regroup+xml"

// regroup is one active temporary group.
type regroup struct {
	tgi           string
	preconfigured string
	constituents  []string
	createdBy     string
}

type regroupState struct {
	mu       sync.RWMutex
	byTGI    map[string]*regroup // lower(TGI) → regroup
	byMember map[string]string   // lower(constituent group URI) → lower(TGI)
}

func newRegroupState() *regroupState {
	return &regroupState{byTGI: map[string]*regroup{}, byMember: map[string]string{}}
}

func (r *regroupState) create(rg *regroup) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(rg.tgi))
	r.byTGI[key] = rg
	for _, c := range rg.constituents {
		r.byMember[strings.ToLower(strings.TrimSpace(c))] = key
	}
}

func (r *regroupState) remove(tgi string) (*regroup, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(tgi))
	rg, ok := r.byTGI[key]
	if !ok {
		return nil, false
	}
	delete(r.byTGI, key)
	for _, c := range rg.constituents {
		delete(r.byMember, strings.ToLower(strings.TrimSpace(c)))
	}
	return rg, true
}

// get returns the regroup for a TGI.
func (r *regroupState) get(tgi string) (*regroup, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rg, ok := r.byTGI[strings.ToLower(strings.TrimSpace(tgi))]
	return rg, ok
}

// regroupedInto returns the TGI a constituent group has been regrouped into.
func (r *regroupState) regroupedInto(groupURI string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tgi, ok := r.byMember[strings.ToLower(strings.TrimSpace(groupURI))]
	if !ok {
		return "", false
	}
	if rg, exists := r.byTGI[tgi]; exists {
		return rg.tgi, true
	}
	return "", false
}

func regroupBody(msg *Message) string {
	if part := msg.Part(ctRegroup); part != nil {
		return string(part.Body)
	}
	if strings.Contains(strings.ToLower(msg.Header("Content-Type")), "mcptt-regroup") {
		return string(msg.Body)
	}
	return ""
}

// regroupGroupList extracts the constituent group URIs from the
// <groups-for-regroup> element (clause 16.2.1.1).
func regroupGroupList(body string) []string {
	inner := xmlElementBody(body, "groups-for-regroup")
	if inner == "" {
		return nil
	}
	var out []string
	text := inner
	for {
		i := strings.Index(text, "<mcpttURI>")
		if i < 0 {
			break
		}
		text = text[i+len("<mcpttURI>"):]
		j := strings.Index(text, "</mcpttURI>")
		if j < 0 {
			break
		}
		if v := strings.TrimSpace(text[:j]); v != "" {
			out = append(out, v)
		}
		text = text[j:]
	}
	if len(out) == 0 {
		// Some clients list plain URIs without the mcpttURI wrapper.
		for _, line := range strings.Split(inner, "<") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "sip:") {
				out = append(out, line)
			}
		}
	}
	return out
}

// handleRegroupMessage implements the controlling side of clauses 16.2.3.1
// (create) and 16.2.3.2 (remove).
func (s *Server) handleRegroupMessage(ctx context.Context, send responder, msg *Message, source string) {
	body := regroupBody(msg)
	action := strings.ToLower(strings.TrimSpace(xmlElementText(body, "regroup-action")))
	tgi := strings.TrimSpace(xmlElementText(xmlElementBody(body, "mcptt-regroup-uri"), "mcpttURI"))
	if tgi == "" {
		tgi = strings.TrimSpace(xmlElementText(body, "mcptt-regroup-uri"))
	}
	requester := identityFrom(msg)

	switch action {
	case "create":
		preconfigured := strings.TrimSpace(xmlElementText(xmlElementBody(body, "preconfigured-group"), "mcpttURI"))
		if preconfigured == "" {
			preconfigured = strings.TrimSpace(xmlElementText(body, "preconfigured-group"))
		}
		constituents := regroupGroupList(body)
		slog.Info("MCPTT regroup create", "tgi", tgi, "preconfigured", preconfigured,
			"constituents", len(constituents), "by", requester, "source", source)

		// Step 2: the preconfigured group must be one this function serves.
		if tgi == "" || s.groupByURI(ctx, preconfigured) == nil || len(constituents) == 0 {
			s.respond(send, msg, 480, "Temporarily Unavailable", nil, nil)
			return
		}
		// Step 3: the proposed regroup identity must be free.
		if _, exists := s.regroups.get(tgi); exists {
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("165 group ID for regroup already in use")}, nil)
			return
		}
		// Every constituent must be a group this function serves (the
		// per-constituent non-controlling exchange of step 4 is local).
		var served []string
		for _, c := range constituents {
			if s.groupByURI(ctx, c) == nil {
				s.respond(send, msg, 480, "Temporarily Unavailable", nil, nil)
				return
			}
			served = append(served, c)
		}

		s.regroups.create(&regroup{
			tgi: tgi, preconfigured: preconfigured, constituents: served, createdBy: requester,
		})
		// Step 6: 200 once every constituent accepted.
		s.respond(send, msg, 200, "OK", nil, nil)
		// Clause 16.2.2.4: notify the affiliated members of each constituent
		// group that the regroup now exists.
		s.notifyRegroupChange(ctx, served, tgi, requester, "create")

	case "remove":
		slog.Info("MCPTT regroup remove", "tgi", tgi, "by", requester, "source", source)
		// Step 2: a regroup in an in-progress emergency state cannot be
		// removed.
		if s.groupPriorityState(tgi) == "emergency" {
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("169 user not authorised to remove regroup in an emergency state")}, nil)
			return
		}
		rg, ok := s.regroups.remove(tgi)
		if !ok {
			// Step 3: unknown regroup identity.
			s.respond(send, msg, 403, "Forbidden",
				[]header{s.mcpttWarning("163 the group identity indicated in the request does not exist")}, nil)
			return
		}
		s.respond(send, msg, 200, "OK", nil, nil)
		s.notifyRegroupChange(ctx, rg.constituents, tgi, requester, "remove")

	default:
		s.respond(send, msg, 400, "Bad Request", nil, nil)
	}
}

// notifyRegroupChange tells the affiliated members of the constituent groups
// that a regroup was created or removed (clauses 16.2.2.4 / 16.2.2.5).
func (s *Server) notifyRegroupChange(ctx context.Context, constituents []string, tgi, requester, action string) {
	notified := map[string]bool{}
	for _, groupURI := range constituents {
		group := s.groupByURI(ctx, groupURI)
		if group == nil {
			continue
		}
		for _, impu := range s.affiliatedGroupMembers(ctx, group.ID, requester) {
			if notified[strings.ToLower(impu)] {
				continue
			}
			notified[strings.ToLower(impu)] = true
			body := fmt.Sprintf(
				`<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>`+
					`<mcptt-request-uri><mcpttURI>%s</mcpttURI></mcptt-request-uri>`+
					`<mcptt-calling-group-id><mcpttURI>%s</mcpttURI></mcptt-calling-group-id>`+
					`</mcptt-Params></mcpttinfo>`, impu, groupURI)
			regroupInfo := fmt.Sprintf(
				`<mcpttregroupinfo xmlns="urn:3gpp:ns:mcpttRegroupInfo:1.0">`+
					`<regroup-action>%s</regroup-action>`+
					`<mcptt-regroup-uri><mcpttURI>%s</mcpttURI></mcptt-regroup-uri>`+
					`</mcpttregroupinfo>`, action, tgi)
			s.sendMcpttMessageWithParts(ctx, impu, []messagePart{
				{contentType: "application/vnd.3gpp.mcptt-info+xml", body: body},
				{contentType: ctRegroup, body: regroupInfo},
			})
		}
	}
}

// regroupConstituents returns the constituent groups of a TGI, or nil.
func (s *Server) regroupConstituents(groupURI string) []string {
	rg, ok := s.regroups.get(groupURI)
	if !ok {
		return nil
	}
	return rg.constituents
}

// admitRegroupInvite is the admission check for a call on a TGI: the caller
// must be an affiliated member of at least one constituent group (clause
// 10.1.1.4.2 with the regroup clarifications).
func (s *Server) admitRegroupInvite(ctx context.Context, initiatorURI string, constituents []string) admissionVerdict {
	for _, groupURI := range constituents {
		userID, groupID, ok := s.userGroupIDs(ctx, initiatorURI, groupURI)
		if !ok {
			continue
		}
		member, _ := s.st.IsGroupMember(ctx, userID, groupID)
		if !member {
			continue
		}
		if affiliated, _ := s.st.IsGroupAffiliated(ctx, userID, groupID); affiliated {
			return admissionVerdict{Admitted: true}
		}
	}
	return admissionVerdict{Status: 403, Reason: "Forbidden",
		Warning: "120 user is not affiliated to this group"}
}

// regroupMembers returns the affiliated members of every constituent group,
// deduplicated, excluding the initiator.
func (s *Server) regroupMembers(ctx context.Context, constituents []string, initiatorURI string) []string {
	seen := map[string]bool{}
	var out []string
	for _, groupURI := range constituents {
		group := s.groupByURI(ctx, groupURI)
		if group == nil {
			continue
		}
		for _, impu := range s.affiliatedGroupMembers(ctx, group.ID, initiatorURI) {
			key := strings.ToLower(impu)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, impu)
		}
	}
	return out
}

// establishRegroupLegs invites the members of every constituent group for a
// call on the TGI.
func (s *Server) establishRegroupLegs(ctx context.Context, txCallID, tgi, initiatorURI string, constituents []string, txSDP sdpInfo) {
	audioPayload := "114 96 9 0 8"
	if len(txSDP.Audio.Payloads) > 0 {
		audioPayload = strings.Join(txSDP.Audio.Payloads, " ")
	}
	regs, err := s.st.ListRegistrations(ctx)
	if err != nil {
		return
	}
	regByImpu := map[string]store.Registration{}
	for _, r := range regs {
		if r.Registered {
			regByImpu[strings.TrimSpace(r.PublicIdentity)] = r
		}
	}
	for _, impu := range s.regroupMembers(ctx, constituents, initiatorURI) {
		reg, ok := regByImpu[impu]
		if !ok {
			continue
		}
		mode := s.answerModeFor(ctx, impu)
		if mode == answerModeUnknown {
			slog.Warn("regroup leg skipped: no usable poc-settings", "member", impu,
				"warning", "146 T-PF unable to determine the service settings for the called user")
			continue
		}
		s.sendRXInvite(context.Background(), txCallID, tgi, initiatorURI, impu, audioPayload, "prearranged", reg, mode, nil)
	}
}

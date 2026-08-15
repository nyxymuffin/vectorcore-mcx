package cms

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"log/slog"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

// Authorised client document management (TS 24.481 clause 6 for group
// documents, TS 24.484 clause 6.3.13 for user profiles): PUTs to the
// generated application usages are accepted and applied into the store, which
// stays the single source of truth - a GET afterwards serves the regenerated
// document. Elements the store does not model are not persisted; the response
// ETag is that of the regenerated document so clients immediately see the
// canonical form.
//
// Writes require an authenticated identity when cms.require_authorization is
// enabled; group modification is limited to the document owner or a member
// with an administrator role (TS 24.481 clause 6.3.3 authorisation, stood in
// for by membership roles).

// handleGeneratedPut applies a PUT to a generated AUID. Returns true when the
// request was handled.
func (s *Server) handleGeneratedPut(w http.ResponseWriter, r *http.Request, path string, body string) bool {
	switch auidFromPath(path) {
	case "org.openmobilealliance.groups":
		s.putGroupDocument(w, r, path, body)
		return true
	case "org.3gpp.mcptt.user-profile":
		s.putUserProfile(w, r, path, body)
		return true
	default:
		return false
	}
}

func (s *Server) putGroupDocument(w http.ResponseWriter, r *http.Request, path, body string) {
	ctx := r.Context()
	groupURI := gmsGroupURIFromPath(path)
	if groupURI == "" {
		groupURI = strings.TrimSpace(xmlAttrOf(body, "list-service", "uri"))
	}
	if groupURI == "" {
		setXCAPResult(r, "bad_group_document")
		writeXCAPError(w, http.StatusConflict, xcapErrorBody("constraint-failure", "no group URI in path or list-service"))
		return
	}
	docURI := strings.TrimSpace(xmlAttrOf(body, "list-service", "uri"))
	if docURI != "" && !strings.EqualFold(docURI, groupURI) {
		setXCAPResult(r, "bad_group_document")
		writeXCAPError(w, http.StatusConflict, xcapErrorBody("constraint-failure", "list-service uri does not match the document selector"))
		return
	}

	// Member entries must resolve to provisioned users (TS 24.481: group
	// members are MC service users; an unknown ID cannot be affiliated).
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type resolved struct {
		user store.User
		role string
	}
	var members []resolved
	for _, entry := range xmlEntries(body) {
		found := false
		for _, u := range users {
			if strings.EqualFold(strings.TrimSpace(u.IMPU), entry.uri) ||
				strings.EqualFold(strings.TrimSpace(u.MCPTTID), entry.uri) {
				members = append(members, resolved{user: u, role: valueOr(entry.participantType, "MCPTT User")})
				found = true
				break
			}
		}
		if !found {
			setXCAPResult(r, "unknown_member")
			writeXCAPError(w, http.StatusConflict, xcapErrorBody("constraint-failure",
				fmt.Sprintf("member %s is not a provisioned MC service user", entry.uri)))
			return
		}
	}

	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var existing *store.Group
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g.URI), groupURI) {
			candidate := g
			existing = &candidate
			break
		}
	}

	// Authorisation for modification (creation is open to authenticated
	// served users): the requester must be a member with an administrator
	// role when the group already exists and authorisation is enforced.
	if existing != nil && s.cfg.CMS.RequireAuthorization {
		if !s.mayManageGroup(ctx, xcapIdentity(r), existing.ID) {
			setXCAPResult(r, "not_authorised")
			writeXCAPError(w, http.StatusConflict, xcapErrorBody("constraint-failure",
				"requester is not authorised to modify this group document"))
			return
		}
	}

	group := store.Group{
		URI:         groupURI,
		DisplayName: strings.TrimSpace(cmsElementText(body, "display-name")),
		Enabled:     !strings.EqualFold(strings.TrimSpace(cmsElementText(body, "on-network-disabled")), "true"),
		ChatGroup:   !strings.EqualFold(strings.TrimSpace(cmsElementText(body, "on-network-invite-members")), "true"),
		MultiTalker: strings.EqualFold(strings.TrimSpace(cmsElementText(body, "multi-talker-control")), "true"),
		AllowEmergencyCall: strings.EqualFold(
			strings.TrimSpace(cmsElementText(body, "allow-MCPTT-emergency-call")), "true"),
		MaxDurationSeconds: xsDurationSeconds(cmsElementText(body, "on-network-maximum-duration")),
	}
	created := false
	if existing == nil {
		madeGroup, err := s.st.CreateGroup(ctx, group)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		existing = &madeGroup
		created = true
	} else {
		group.ID = existing.ID
		group.MaxSimultaneousTalkers = existing.MaxSimultaneousTalkers
		if _, err := s.st.UpdateGroup(ctx, existing.ID, group); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Reconcile memberships with the document's member list.
	current, err := s.st.ListGroupMemberships(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	wanted := map[string]string{}
	for _, m := range members {
		wanted[m.user.ID] = m.role
	}
	for _, m := range current {
		if m.GroupID != existing.ID {
			continue
		}
		if role, keep := wanted[m.UserID]; keep {
			if m.Role != role {
				m.Role = role
				if _, err := s.st.UpdateGroupMembership(ctx, m.ID, m); err != nil {
					slog.Warn("group doc PUT: membership role update failed", "err", err)
				}
			}
			delete(wanted, m.UserID)
		} else {
			if err := s.st.DeleteGroupMembership(ctx, m.ID); err != nil {
				slog.Warn("group doc PUT: membership delete failed", "err", err)
			}
		}
	}
	for userID, role := range wanted {
		if _, err := s.st.CreateGroupMembership(ctx, store.GroupMembership{
			UserID: userID, GroupID: existing.ID, Role: role,
		}); err != nil {
			slog.Warn("group doc PUT: membership create failed", "err", err)
		}
	}

	slog.Info("GMS group document written", "group_uri", groupURI, "created", created,
		"members", len(members), "by", xcapIdentity(r))
	s.documentChanged(path)
	regenerated := s.defaultGMSGroup(ctx, path)
	w.Header().Set("ETag", ContentETag(regenerated))
	if created {
		setXCAPResult(r, "created")
		w.WriteHeader(http.StatusCreated)
	} else {
		setXCAPResult(r, "updated")
		w.WriteHeader(http.StatusNoContent)
	}
}

// deleteGroupDocument handles DELETE of a group document (TS 24.481 clause
// 6.3.5): the group and its memberships are removed.
func (s *Server) deleteGroupDocument(w http.ResponseWriter, r *http.Request, path string) bool {
	if auidFromPath(path) != "org.openmobilealliance.groups" {
		return false
	}
	ctx := r.Context()
	groupURI := gmsGroupURIFromPath(path)
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	for _, g := range groups {
		if !strings.EqualFold(strings.TrimSpace(g.URI), strings.TrimSpace(groupURI)) {
			continue
		}
		if s.cfg.CMS.RequireAuthorization && !s.mayManageGroup(ctx, xcapIdentity(r), g.ID) {
			setXCAPResult(r, "not_authorised")
			writeXCAPError(w, http.StatusConflict, xcapErrorBody("constraint-failure",
				"requester is not authorised to delete this group document"))
			return true
		}
		if err := s.st.DeleteGroup(ctx, g.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		slog.Info("GMS group document deleted", "group_uri", groupURI, "by", xcapIdentity(r))
		s.documentChanged(path)
		setXCAPResult(r, "deleted")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	setXCAPResult(r, "not_found")
	http.Error(w, "group document not found", http.StatusNotFound)
	return true
}

// putUserProfile applies the client-manageable parts of a user profile
// (TS 24.484 clause 6.3.13): display name and the FunctionalAliasList.
// Identity, group membership and authorisation flags stay provisioning-owned.
func (s *Server) putUserProfile(w http.ResponseWriter, r *http.Request, path, body string) {
	ctx := r.Context()
	xui := xcapUserFromPath(path)
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user := findUserByXUI(users, xui)
	if user.ID == "" {
		setXCAPResult(r, "not_found")
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	// A user may modify their own profile; anyone else is refused when
	// authorisation is enforced.
	if s.cfg.CMS.RequireAuthorization {
		id := xcapIdentity(r)
		if !strings.EqualFold(id, strings.TrimSpace(user.IMPU)) &&
			!strings.EqualFold(id, strings.TrimSpace(user.MCPTTID)) {
			setXCAPResult(r, "not_authorised")
			writeXCAPError(w, http.StatusConflict, xcapErrorBody("constraint-failure",
				"requester may only modify their own user profile"))
			return
		}
	}

	if v := strings.TrimSpace(cmsElementText(xmlElementBodyOf(body, "MCPTTUserID"), "display-name")); v != "" {
		user.DisplayName = v
	}
	if faBody := xmlElementBodyOf(body, "FunctionalAliasList"); faBody != "" {
		var aliases []string
		for _, entry := range strings.Split(faBody, "<uri-entry>") {
			if i := strings.Index(entry, "</uri-entry>"); i >= 0 {
				if alias := strings.TrimSpace(entry[:i]); alias != "" {
					aliases = append(aliases, alias)
				}
			}
		}
		user.FunctionalAliases = aliases
	}
	if _, err := s.st.UpdateUser(ctx, user.ID, user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("user profile document written", "user", user.MCPTTID, "by", xcapIdentity(r))
	s.documentChanged(path)
	regenerated := s.defaultUserProfile(ctx, path)
	w.Header().Set("ETag", ContentETag(regenerated))
	setXCAPResult(r, "updated")
	w.WriteHeader(http.StatusNoContent)
}

// mayManageGroup reports whether an identity may modify a group: an
// administrator-role member of it (TS 24.481 clause 6.3.3 authorisation
// stand-in).
func (s *Server) mayManageGroup(ctx context.Context, identity, groupID string) bool {
	if strings.TrimSpace(identity) == "" {
		return false
	}
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return false
	}
	userID := ""
	for _, u := range users {
		if strings.EqualFold(strings.TrimSpace(u.IMPU), identity) ||
			strings.EqualFold(strings.TrimSpace(u.MCPTTID), identity) {
			userID = u.ID
			break
		}
	}
	if userID == "" {
		return false
	}
	memberships, err := s.st.ListGroupMemberships(ctx)
	if err != nil {
		return false
	}
	for _, m := range memberships {
		if m.GroupID == groupID && m.UserID == userID &&
			strings.EqualFold(m.Role, "MCPTT Administrator") {
			return true
		}
	}
	return false
}

// --- small XML helpers for the write path ---

type memberEntry struct {
	uri             string
	participantType string
}

// xmlEntries returns the <entry uri=...> elements of the document's <list>.
func xmlEntries(body string) []memberEntry {
	var out []memberEntry
	text := body
	for {
		i := strings.Index(text, "<entry")
		if i < 0 {
			return out
		}
		text = text[i:]
		end := strings.Index(text, ">")
		if end < 0 {
			return out
		}
		entry := memberEntry{uri: strings.TrimSpace(xmlAttrValue(text[:end], "uri"))}
		if close := strings.Index(text, "</entry>"); close > end {
			entry.participantType = strings.TrimSpace(cmsElementText(text[end:close], "participant-type"))
		}
		if entry.uri != "" {
			out = append(out, entry)
		}
		text = text[end:]
	}
}

// cmsElementText returns the trimmed leading text of the first occurrence of
// an element (enough for the simple-typed elements the write path reads).
func cmsElementText(body, element string) string {
	inner := xmlElementBodyOf(body, element)
	if i := strings.IndexByte(inner, '<'); i >= 0 {
		inner = inner[:i]
	}
	return strings.TrimSpace(inner)
}

// xmlAttrOf returns an attribute of the first occurrence of an element.
func xmlAttrOf(body, element, attr string) string {
	i := strings.Index(body, "<"+element)
	if i < 0 {
		if j := strings.Index(body, ":"+element); j >= 0 {
			i = strings.LastIndex(body[:j], "<")
			if i < 0 {
				return ""
			}
		} else {
			return ""
		}
	}
	rest := body[i:]
	end := strings.Index(rest, ">")
	if end < 0 {
		return ""
	}
	return xmlAttrValue(rest[:end], attr)
}

// xmlAttrValue extracts a quoted attribute from an element open tag.
func xmlAttrValue(tag, name string) string {
	i := strings.Index(tag, name+`="`)
	if i < 0 {
		return ""
	}
	rest := tag[i+len(name)+2:]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

// xmlElementBodyOf returns the inner content of the first occurrence of an
// element, accepting an optional namespace prefix on the tag.
func xmlElementBodyOf(body, element string) string {
	re := regexp.MustCompile(`(?s)<(?:[A-Za-z0-9_.-]+:)?` + regexp.QuoteMeta(element) +
		`(?:\s[^>]*)?>(.*?)</(?:[A-Za-z0-9_.-]+:)?` + regexp.QuoteMeta(element) + `>`)
	if m := re.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// xsDurationSeconds parses the PT{n}S / PT{n}M / PT{n}H forms of xs:duration
// the group documents use; anything else is 0 (no limit).
func xsDurationSeconds(v string) int {
	v = strings.TrimSpace(strings.ToUpper(v))
	if !strings.HasPrefix(v, "PT") || len(v) < 4 {
		return 0
	}
	unit := v[len(v)-1]
	n, err := strconv.Atoi(v[2 : len(v)-1])
	if err != nil || n < 0 {
		return 0
	}
	switch unit {
	case 'S':
		return n
	case 'M':
		return n * 60
	case 'H':
		return n * 3600
	}
	return 0
}

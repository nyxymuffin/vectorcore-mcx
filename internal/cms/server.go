package cms

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/tlsutil"
)

type Server struct {
	cfg config.Config
	st  store.Store
}

func NewServer(cfg config.Config, st store.Store) *Server {
	return &Server{cfg: cfg, st: st}
}

func (s *Server) Start(ctx context.Context) error {
	if !s.cfg.CMS.Enabled {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/xcap-root/", s.handleXCAP)
	mux.HandleFunc("/xcap-root", s.handleXCAP)
	tlsConf, err := tlsutil.ServerConfig(s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("cms listener: %w", err)
	}
	srv := &http.Server{
		Addr:         s.cfg.CMS.Listen,
		Handler:      logRequests(mux),
		TLSConfig:    tlsConf,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		serve := srv.ListenAndServe
		if tlsConf != nil {
			serve = func() error { return srv.ListenAndServeTLS("", "") }
		}
		slog.Info("CMS/XCAP server listening", "addr", s.cfg.CMS.Listen, "tls", tlsConf != nil)
		if err := serve(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleXCAP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/xcap-root")
	if path == "" {
		path = "/"
	}
	switch r.Method {
	case http.MethodGet:
		s.get(w, r, path)
	case http.MethodPut:
		s.put(w, r, path)
	case http.MethodDelete:
		s.delete(w, r, path)
	default:
		setXCAPResult(r, "method_not_allowed")
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, path string) {
	if path == "/" {
		setXCAPResult(r, "index")
		docs, err := s.st.ListCMSDocuments(r.Context())
		if err != nil {
			setXCAPResult(r, "store_error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><xcap-root>`)
		for _, doc := range docs {
			fmt.Fprintf(&b, `<document path=%q auid=%q content-type=%q />`, doc.Path, doc.AUID, doc.ContentType)
		}
		b.WriteString(`</xcap-root>`)
		writeXML(w, b.String())
		return
	}

	docPath, nodeSelector := splitNodeSelector(path)

	var body, docContentType string
	switch {
	case isGeneratedDocumentAUID(auidFromPath(docPath)):
		setXCAPResult(r, "default")
		body = s.defaultDocumentForRequest(r, docPath)
		docContentType = contentTypeForPath(docPath)
	default:
		doc, err := s.st.GetCMSDocumentByPath(r.Context(), docPath)
		if err != nil {
			setXCAPResult(r, "store_error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if doc == nil {
			// RFC 4825 clause 8.2.1: a document that does not exist is a 404.
			// Unknown application usages are no longer answered with an
			// invented placeholder document.
			setXCAPResult(r, "not_found")
			http.Error(w, "document not found", http.StatusNotFound)
			return
		}
		setXCAPResult(r, "stored")
		body = doc.Body
		docContentType = valueOr(doc.ContentType, contentTypeForPath(docPath))
	}

	tag := ContentETag(body)
	// RFC 2616 conditional GET: the ETag is always the full document's, also
	// for node-selector fetches (RFC 4825 clause 7.10).
	if match := strings.TrimSpace(r.Header.Get("If-None-Match")); match != "" && (match == "*" || etagMatches(match, tag)) {
		setXCAPResult(r, "not_modified")
		w.Header().Set("ETag", tag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if nodeSelector != "" {
		fragment, isAttr, found, err := selectNode(body, nodeSelector)
		if err != nil {
			setXCAPResult(r, "bad_node_selector")
			writeXCAPError(w, http.StatusConflict, xcapErrorBody("cannot-insert", err.Error()))
			return
		}
		if !found {
			setXCAPResult(r, "node_not_found")
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
		contentType := "application/xcap-el+xml"
		if isAttr {
			contentType = "application/xcap-att+xml"
		}
		setXCAPResult(r, "node")
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", tag)
		w.Header().Set("Content-Length", fmt.Sprint(len(fragment)))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fragment))
		slog.Info("xcap_get_node", "auid", auidFromPath(docPath), "path", docPath, "node", nodeSelector, "attr", isAttr, "etag", tag, "response_bytes", len(fragment))
		return
	}

	w.Header().Set("Content-Type", docContentType)
	w.Header().Set("ETag", tag)
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(body))
	slog.Info("xcap_get", "auid", auidFromPath(docPath), "path", docPath, "etag", tag, "status", http.StatusOK, "response_bytes", len(body))
}

// etagMatches compares an If-Match/If-None-Match header against the current
// entity tag, accepting a comma-separated list.
func etagMatches(headerValue, tag string) bool {
	for _, candidate := range strings.Split(headerValue, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == tag {
			return true
		}
	}
	return false
}

func writeXCAPError(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/xcap-error+xml")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, path string) {
	// Documents under the generated application usages are derived live from
	// provisioning state; storing a client's copy would either shadow the
	// generated content or silently diverge from what GET returns. RFC 4825
	// clause 8.2.2 allows the server to refuse with a constraint failure.
	if isGeneratedDocumentAUID(auidFromPath(path)) {
		setXCAPResult(r, "generated_readonly")
		writeXCAPError(w, http.StatusConflict,
			xcapErrorBody("constraint-failure", "document is generated from provisioning state; modify users/groups via the management API"))
		return
	}
	if docPath, node := splitNodeSelector(path); node != "" {
		// Node-selector PUT/DELETE (partial document mutation, RFC 4825
		// clauses 8.2.3/8.2.5) is not offered; stored documents are managed
		// whole.
		_ = docPath
		setXCAPResult(r, "node_write_unsupported")
		writeXCAPError(w, http.StatusConflict,
			xcapErrorBody("cannot-insert", "partial document modification is not supported"))
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		setXCAPResult(r, "read_error")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	contentType := valueOr(r.Header.Get("Content-Type"), "application/xml")
	existing, err := s.st.GetCMSDocumentByPath(r.Context(), path)
	if err != nil {
		setXCAPResult(r, "store_error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Conditional operations, RFC 4825 clause 7.11: If-Match against the
	// current entity, If-None-Match: * to require creation.
	currentTag := ""
	if existing != nil {
		currentTag = ContentETag(existing.Body)
	}
	if match := strings.TrimSpace(r.Header.Get("If-Match")); match != "" {
		if existing == nil || !etagMatches(match, currentTag) {
			setXCAPResult(r, "precondition_failed")
			http.Error(w, "precondition failed", http.StatusPreconditionFailed)
			return
		}
	}
	if match := strings.TrimSpace(r.Header.Get("If-None-Match")); match != "" && existing != nil && (match == "*" || etagMatches(match, currentTag)) {
		setXCAPResult(r, "precondition_failed")
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return
	}
	doc := store.CMSDocument{
		Name:        strings.Trim(path, "/"),
		AUID:        auidFromPath(path),
		Path:        path,
		ContentType: contentType,
		Body:        string(body),
	}
	if existing == nil {
		if _, err := s.st.CreateCMSDocument(r.Context(), doc); err != nil {
			setXCAPResult(r, "store_error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		setXCAPResult(r, "created")
		w.Header().Set("ETag", etag(string(body)))
		w.WriteHeader(http.StatusCreated)
		return
	}
	if _, err := s.st.UpdateCMSDocument(r.Context(), existing.ID, doc); err != nil {
		setXCAPResult(r, "store_error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setXCAPResult(r, "updated")
	w.Header().Set("ETag", etag(string(body)))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request, path string) {
	if isGeneratedDocumentAUID(auidFromPath(path)) {
		setXCAPResult(r, "generated_readonly")
		writeXCAPError(w, http.StatusConflict,
			xcapErrorBody("constraint-failure", "document is generated from provisioning state; modify users/groups via the management API"))
		return
	}
	doc, err := s.st.GetCMSDocumentByPath(r.Context(), path)
	if err != nil {
		setXCAPResult(r, "store_error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if doc == nil {
		// RFC 4825 clause 8.2.5: deleting a resource that does not exist is
		// a 404, not a silent success.
		setXCAPResult(r, "not_found")
		http.Error(w, "document not found", http.StatusNotFound)
		return
	}
	if match := strings.TrimSpace(r.Header.Get("If-Match")); match != "" && !etagMatches(match, ContentETag(doc.Body)) {
		setXCAPResult(r, "precondition_failed")
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return
	}
	if err := s.st.DeleteCMSDocument(r.Context(), doc.ID); err != nil {
		setXCAPResult(r, "store_error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setXCAPResult(r, "deleted")
	w.WriteHeader(http.StatusNoContent)
}

func writeXML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("ETag", ContentETag(body))
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(body))
}

func contentTypeForPath(path string) string {
	switch auidFromPath(path) {
	case "xcap-caps":
		return "application/xcap-caps+xml"
	case "org.3gpp.mcptt.ue-init-config":
		return "application/vnd.3gpp.mcptt-ue-init-config+xml"
	case "org.3gpp.mcptt.ue-config":
		return "application/vnd.3gpp.mcptt-ue-config+xml"
	case "org.3gpp.mcptt.user-profile":
		return "application/vnd.3gpp.mcptt-user-profile+xml"
	case "org.3gpp.mcptt.service-config":
		return "application/vnd.3gpp.mcptt-service-config+xml"
	case "org.openmobilealliance.groups":
		return "application/vnd.oma.poc.groups+xml"
	default:
		return "application/xml"
	}
}

func (s *Server) defaultDocument(ctx context.Context, path string) string {
	return s.DefaultDocument(ctx, path)
}

func (s *Server) defaultDocumentForRequest(r *http.Request, path string) string {
	if auidFromPath(path) == "org.3gpp.mcptt.ue-init-config" {
		sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		return s.defaultUEInitConfigForIP(r.Context(), path, sourceIP)
	}
	return s.DefaultDocument(r.Context(), path)
}

// isGeneratedDocumentAUID reports whether DefaultDocument can derive this
// document live from current store state (users/groups/memberships, etc.).
// Such documents must always be regenerated on GET rather than served from a
// stored cms_documents row: a one-time PUT (e.g. from provisioning or test
// tooling) would otherwise freeze stale content — such as a user's group
// membership list — that no longer matches the database.
//
// Keep this in sync with the case list in DefaultDocument's switch.
func isGeneratedDocumentAUID(auid string) bool {
	switch auid {
	case "xcap-caps",
		"org.3gpp.mcptt.ue-init-config",
		"org.3gpp.mcptt.ue-config",
		"org.3gpp.mcptt.user-profile",
		"org.3gpp.mcptt.service-config",
		"org.openmobilealliance.groups":
		return true
	default:
		return false
	}
}

func (s *Server) DefaultDocument(ctx context.Context, path string) string {
	switch auidFromPath(path) {
	case "xcap-caps":
		return defaultXCAPCaps()
	case "org.3gpp.mcptt.ue-init-config":
		return s.defaultUEInitConfig(ctx, path)
	case "org.3gpp.mcptt.ue-config":
		return s.defaultUEConfig(ctx, path)
	case "org.3gpp.mcptt.user-profile":
		return s.defaultUserProfile(ctx, path)
	case "org.3gpp.mcptt.service-config":
		return s.defaultServiceConfig()
	case "org.openmobilealliance.groups":
		return s.defaultGMSGroup(ctx, path)
	default:
		// Unknown application usages have no generated form; the GET path
		// answers 404 for them (RFC 4825 clause 8.2.1).
		return ""
	}
}

func (s *Server) defaultUEInitConfig(ctx context.Context, path string) string {
	return s.defaultUEInitConfigForIP(ctx, path, "")
}

func (s *Server) defaultUEInitConfigForIP(ctx context.Context, path, sourceIP string) string {
	ueID := xcapUserFromPath(path)
	if ueID == "" {
		ueID = "mcptt_UE_id"
	}
	ueXUI := s.ueXUIURIForIP(ctx, sourceIP)
	ueInstanceURN := s.ueInstanceIDURN()
	root := strings.TrimRight(s.cfg.CMS.XCAPRoot, "/")
	realm := s.cfg.IMS.Realm
	cmsURI := s.cfg.MCX.CMSURI
	gmsURI := s.cfg.MCX.GMSURI
	kmsURI := s.cfg.MCX.KMSURI
	idmsAuth := s.cfg.MCX.IDMSAuthEndpoint
	idmsToken := s.cfg.MCX.IDMSTokenEndpoint
	httpProxy := s.cfg.MCX.HTTPProxyURI
	plmn := s.plmn()

	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<mcptt-UE-initial-configuration domain=%q XUI-URI=%q xmlns="urn:3gpp:mcptt:mcpttUEinitConfig:1.0">
  <name xml:lang="en" index="0">VectorCore MCX UE Initial Configuration</name>
  <mcptt-UE-id index="0">
    <Instance-ID-URN>%s</Instance-ID-URN>
  </mcptt-UE-id>
  <Default-user-profile User-ID="default" user-profile-index="0" index="0"/>
  <on-network index="0">
    <Timers>
      <T100>0</T100>
      <T101>0</T101>
      <T103>0</T103>
      <T104>0</T104>
      <T132>0</T132>
	    </Timers>
    <HPLMN PLMN="%s">
      <service>
        <MCPTT-to-con-ref>%s</MCPTT-to-con-ref>
        <MC-common-core-to-con-ref>%s</MC-common-core-to-con-ref>
        <MC-ID-to-con-ref>%s</MC-ID-to-con-ref>
      </service>
      <VPLMN PLMN="%s">
        <service>
          <MCPTT-to-con-ref>%s</MCPTT-to-con-ref>
          <MC-common-core-to-con-ref>%s</MC-common-core-to-con-ref>
          <MC-ID-to-con-ref>%s</MC-ID-to-con-ref>
        </service>
      </VPLMN>
    </HPLMN>
	    <App-Server-Info>
      <idms-auth-endpoint>%s</idms-auth-endpoint>
      <idms-token-endpoint>%s</idms-token-endpoint>
      <http-proxy>%s</http-proxy>
	      <gms>%s</gms>
	      <cms>%s</cms>
	      <kms>%s</kms>
      <tls-tunnel-auth-method>
        <mutual-authentication>false</mutual-authentication>
      </tls-tunnel-auth-method>
    </App-Server-Info>
    <GMS-URI>%s</GMS-URI>
    <group-creation-XUI>%s</group-creation-XUI>
    <GMS-XCAP-root-URI>%s</GMS-XCAP-root-URI>
    <CMS-XCAP-root-URI>%s</CMS-XCAP-root-URI>
    <integrity-protection-enabled>false</integrity-protection-enabled>
    <confidentiality-protection-enabled>false</confidentiality-protection-enabled>
  </on-network>
  <off-network index="0">
    <Timers>
      <TFG1>1000</TFG1>
      <TFG2>5000</TFG2>
      <TFG3>5000</TFG3>
      <TFG4>5</TFG4>
      <TFG5>5</TFG5>
      <TFG11>1000</TFG11>
      <TFG12>5000</TFG12>
      <TFG13>5</TFG13>
      <TFG14>5</TFG14>
      <TFP1>1000</TFP1>
      <TFP2>5</TFP2>
      <TFP3>5000</TFP3>
      <TFP4>5000</TFP4>
      <TFP5>5000</TFP5>
      <TFP6>5000</TFP6>
      <TFP7>5</TFP7>
      <TFB1>1000</TFB1>
      <TFB2>5</TFB2>
      <TFB3>5</TFB3>
      <T201>1000</T201>
      <T203>5</T203>
      <T204>5</T204>
      <T205>5</T205>
      <T230>5</T230>
      <T233>5</T233>
      <TFE1>1000</TFE1>
      <TFE2>5</TFE2>
    </Timers>
    <Counters>
      <CFP1>3</CFP1>
      <CFP3>3</CFP3>
      <CFP4>3</CFP4>
      <CFP6>3</CFP6>
      <CFG11>3</CFG11>
      <CFG12>3</CFG12>
      <C201>3</C201>
      <C204>3</C204>
      <C205>3</C205>
    </Counters>
  </off-network>
</mcptt-UE-initial-configuration>`,
		realm,
		xmlText(ueXUI),
		xmlText(ueInstanceURN),
		xmlText(plmn),
		xmlText(cmsURI),
		xmlText(cmsURI),
		xmlText(cmsURI),
		xmlText(plmn),
		xmlText(cmsURI),
		xmlText(cmsURI),
		xmlText(cmsURI),
		xmlText(idmsAuth),
		xmlText(idmsToken),
		xmlText(httpProxy),
		xmlText(gmsURI),
		xmlText(cmsURI),
		xmlText(kmsURI),
		xmlText(gmsURI),
		xmlText(ueXUI),
		xmlText(root),
		xmlText(root),
	)
	slog.Info("CMS UE initial configuration generated",
		"ue_id", ueID,
		"cms_xcap_root", root,
		"gms_xcap_root", root,
		"xui_uri", ueXUI,
		"instance_id_urn", ueInstanceURN,
		"profile", "default/mcptt-user-profile.xml",
	)
	slog.Debug("CMS UE initial configuration body", "body", body)
	return body
}

func (s *Server) defaultUEConfig(ctx context.Context, path string) string {
	users, _ := s.st.ListUsers(ctx)
	groups, _ := s.st.ListGroups(ctx)
	memberships, _ := s.st.ListGroupMemberships(ctx)

	xui := xcapUserFromPath(path)
	user := findUserByXUI(users, xui)
	userURI := userIdentityURI(user)
	displayName := userDisplayName(user)
	priorityEntries := buildGroupPriorityEntries(groups, memberships, user.ID)
	if priorityEntries == "" {
		priorityEntries = groupPriorityEntry(s.cfg.MCX.DefaultGroupURI, 1)
	}
	if userURI == "" {
		userURI = xui
	}
	if xui == "" {
		xui = s.ueXUIURI()
	}
	ueInstanceURN := s.ueInstanceIDURN()
	if userURI == "" {
		userURI = xui
	}
	if displayName == "" {
		displayName = userURI
	}
	realm := s.cfg.IMS.Realm

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<mcptt-UE-configuration domain=%q XUI-URI=%q xmlns="urn:3gpp:mcptt:mcpttUEConfig:1.0">
  <name xml:lang="en">%s</name>
  <mcptt-UE-id index="0">
    <Instance-ID-URN>%s</Instance-ID-URN>
  </mcptt-UE-id>
  <common index="0">
    <private-call>
      <Max-Simul-Call-N10>1</Max-Simul-Call-N10>
    </private-call>
    <MCPTT-Group-Call>
      <Max-Simul-Call-N4>1</Max-Simul-Call-N4>
      <Max-Simul-Trans-N5>1</Max-Simul-Trans-N5>
      <Prioritized-MCPTT-Group>%s
      </Prioritized-MCPTT-Group>
    </MCPTT-Group-Call>
  </common>
  <on-network index="0">
    <IPv6Preferred>false</IPv6Preferred>
    <Relay-Service>false</Relay-Service>
  </on-network>
</mcptt-UE-configuration>`,
		realm,
		xmlText(userURI),
		xmlText(displayName),
		xmlText(ueInstanceURN),
		priorityEntries,
	)
}

func (s *Server) ueXUIURI() string {
	if v := strings.TrimSpace(s.cfg.MCX.UEXUIURI); v != "" {
		return v
	}
	if v := strings.TrimSpace(s.cfg.MCX.DefaultUserIdentity); v != "" {
		return v
	}
	return "sip:mcptt-user@" + strings.TrimSpace(s.cfg.IMS.Realm)
}

func (s *Server) ueXUIURIForIP(ctx context.Context, sourceIP string) string {
	if sourceIP != "" {
		if mcpttID, err := s.st.GetMCPTTIDByUEIP(ctx, sourceIP); err == nil && mcpttID != "" {
			return mcpttID
		}
	}
	return s.ueXUIURI()
}

func (s *Server) ueInstanceIDURN() string {
	if v := strings.TrimSpace(s.cfg.MCX.UEInstanceIDURN); v != "" {
		return v
	}
	return "urn:uuid:00000000-0000-4000-8000-000000000001"
}

func (s *Server) defaultServiceConfig() string {
	realm := s.cfg.IMS.Realm
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<service-configuration-info xmlns="urn:3gpp:ns:mcpttServiceConfig:1.0">
  <service-configuration-params domain=%q>
    <common>
      <min-length-alias>1</min-length-alias>
    </common>
    <on-network>
      <num-levels-priority-hierarchy>15</num-levels-priority-hierarchy>
      <transmit-time>
        <time-limit>PT300S</time-limit>
        <time-warning>PT5S</time-warning>
      </transmit-time>
      <hang-time-warning>PT5S</hang-time-warning>
      <floor-control-queue>
        <depth>10</depth>
        <max-user-request-time>PT30S</max-user-request-time>
      </floor-control-queue>
      <fc-timers-counters>
        <T1-end-of-rtp-media>PT5S</T1-end-of-rtp-media>
        <T3-stop-talking-grace>PT5S</T3-stop-talking-grace>
        <T7-floor-idle>PT5S</T7-floor-idle>
        <T8-floor-revoke>PT5S</T8-floor-revoke>
        <T11-end-of-RTP-dual>PT5S</T11-end-of-RTP-dual>
        <T12-stop-talking-dual>PT5S</T12-stop-talking-dual>
        <T15-conversation>PT30S</T15-conversation>
        <T16-map-group-to-bearer>PT5S</T16-map-group-to-bearer>
        <T17-unmap-group-to-bearer>PT5S</T17-unmap-group-to-bearer>
        <T20-floor-granted>PT5S</T20-floor-granted>
        <T55-connect>PT5S</T55-connect>
        <T56-disconnect>PT5S</T56-disconnect>
        <C7-floor-idle>3</C7-floor-idle>
        <C17-unmap-group-to-bearer>3</C17-unmap-group-to-bearer>
        <C20-floor-granted>3</C20-floor-granted>
        <C55-connect>3</C55-connect>
        <C56-disconnect>3</C56-disconnect>
      </fc-timers-counters>
      <emergency-resource-priority>
        <resource-priority-namespace>mcptt</resource-priority-namespace>
        <resource-priority-priority>0</resource-priority-priority>
      </emergency-resource-priority>
      <imminent-peril-resource-priority>
        <resource-priority-namespace>mcptt</resource-priority-namespace>
        <resource-priority-priority>1</resource-priority-priority>
      </imminent-peril-resource-priority>
      <normal-resource-priority>
        <resource-priority-namespace>mcptt</resource-priority-namespace>
        <resource-priority-priority>5</resource-priority-priority>
      </normal-resource-priority>
    </on-network>
  </service-configuration-params>
</service-configuration-info>`, realm)
}

func (s *Server) defaultGMSGroup(ctx context.Context, path string) string {
	groupURI := gmsGroupURIFromPath(path)
	groups, _ := s.st.ListGroups(ctx)
	memberships, _ := s.st.ListGroupMemberships(ctx)
	users, _ := s.st.ListUsers(ctx)

	group := findGroupByURI(groups, groupURI)
	if group.URI == "" {
		group.URI = groupURI
	}
	if group.URI == "" {
		group.URI = s.cfg.MCX.DefaultGroupURI
	}
	displayName := strings.TrimSpace(group.DisplayName)
	if displayName == "" {
		displayName = group.URI
	}
	members := buildGMSMemberEntries(users, memberships, group.ID)
	// TS 24.481 clause 7.2.2 items z1/e: the <multi-talker-control> element
	// marks a multi-talker group, and <supported-services> with the MCPTT
	// ICSI and <mcptt-speech> group media identifies the document as an MCPTT
	// group document.
	multiTalker := ""
	if group.MultiTalker {
		multiTalker = `
    <mcpttgi:multi-talker-control>true</mcpttgi:multi-talker-control>`
	}
	// TS 24.481 clause 7.2.4.2 <on-network-invite-members>: "true" is a
	// prearranged group (the server invites the members), "false" a chat
	// group (members join themselves).
	inviteMembers := "true"
	if group.ChatGroup {
		inviteMembers = "false"
	}
	multiTalker = fmt.Sprintf(`
    <mcpttgi:on-network-invite-members>%s</mcpttgi:on-network-invite-members>`, inviteMembers) + multiTalker
	// TS 24.481 clause 7.2.4.2 <allow-MCPTT-emergency-call>: whether
	// emergency calls may target this group (consulted by the controlling
	// function per TS 24.379 clause 6.3.3.1.13.2).
	if group.AllowEmergencyCall {
		multiTalker += `
    <mcpttgi:allow-MCPTT-emergency-call>true</mcpttgi:allow-MCPTT-emergency-call>`
	}
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<group xmlns="urn:oma:xml:poc:list-service" xmlns:rl="urn:ietf:params:xml:ns:resource-lists" xmlns:cp="urn:ietf:params:xml:ns:common-policy" xmlns:ocp="urn:oma:xml:xdm:common-policy" xmlns:oxe="urn:oma:xml:xdm:extensions" xmlns:oxg="urn:oma:xml:xdm:group" xmlns:mcpttgi="urn:3gpp:ns:mcpttGroupInfo:1.0">
  <list-service uri="%s">
    <display-name xml:lang="en">%s</display-name>
    <list>%s
    </list>
    <oxg:supported-services>
      <oxg:service enabler="urn:urn-7:3gpp-service.ims.icsi.mcptt">
        <oxg:group-media>
          <mcpttgi:mcptt-speech/>
        </oxg:group-media>
      </oxg:service>
    </oxg:supported-services>
    <max-participant-count>200</max-participant-count>
    <cp:ruleset>
      <cp:rule id="vectorcore-default">
        <cp:conditions/>
        <cp:actions>
          <cp:allow-initiate-conference>true</cp:allow-initiate-conference>
        </cp:actions>
      </cp:rule>
    </cp:ruleset>
    <mcpttgi:on-network-group-priority>1</mcpttgi:on-network-group-priority>%s
  </list-service>
</group>`,
		xmlText(group.URI),
		xmlText(displayName),
		members,
		multiTalker,
	)
	slog.Info("GMS group document generated",
		"path", path,
		"group_uri", group.URI,
		"group_id", group.ID,
		"members", strings.Count(members, "<entry "),
	)
	slog.Debug("GMS group document body", "body", body)
	return body
}

func (s *Server) defaultUserProfile(ctx context.Context, path string) string {
	users, _ := s.st.ListUsers(ctx)
	groups, _ := s.st.ListGroups(ctx)
	memberships, _ := s.st.ListGroupMemberships(ctx)

	xui := xcapUserFromPath(path)
	if isDefaultProfileXUI(xui) {
		return s.defaultDefaultUserProfile()
	}
	user := findUserByXUI(users, xui)
	userURI := userIdentityURI(user)
	displayName := userDisplayName(user)
	groupEntries := buildGroupEntries(groups, memberships, user.ID)
	implicitEntries := buildImplicitAffiliationEntries(groups, memberships, user.ID)
	faEntries := buildFunctionalAliasEntries(user.FunctionalAliases)
	if userURI == "" {
		userURI = xui
	}
	if displayName == "" {
		displayName = userURI
	}
	return userProfileDocument(userURI, displayName, "VectorCore User Profile", groupEntries, implicitEntries, faEntries)
}

func (s *Server) defaultDefaultUserProfile() string {
	defaultURI := s.cfg.MCX.DefaultUserIdentity
	return userProfileDocument(defaultURI, defaultURI, "VectorCore Default Profile", "", "", "")
}

// buildFunctionalAliasEntries renders the <FunctionalAliasList> entries of
// TS 24.484 clause 6.3.13.2.10: the functional aliases the user is authorised
// to activate, matching the list handleFunctionalAliasPublish authorises
// against (TS 24.379 clause 9A.2.2.2.3 step 4A).
func buildFunctionalAliasEntries(aliases []string) string {
	var b strings.Builder
	for _, alias := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		fmt.Fprintf(&b, `
        <entry>
          <uri-entry>%s</uri-entry>
        </entry>`, xmlText(alias))
	}
	return b.String()
}

func (s *Server) plmn() string {
	mcc := strings.TrimSpace(s.cfg.IMS.MCC)
	mnc := strings.TrimSpace(s.cfg.IMS.MNC)
	if mcc == "" || mnc == "" {
		return "00101"
	}
	return mcc + mnc
}

func userProfileDocument(userURI, displayName, name, groupEntries, implicitEntries, faEntries string) string {
	faList := ""
	if faEntries != "" {
		faList = fmt.Sprintf(`
    <anyExt>
      <FunctionalAliasList>%s
      </FunctionalAliasList>
    </anyExt>`, faEntries)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<mcptt-user-profile XUI-URI=%q user-profile-index="0" xmlns="urn:3gpp:mcptt:user-profile:1.0">
  <Name xml:lang="en">%s</Name>
  <Status>true</Status>
  <ProfileName xml:lang="en">mcptt-user-profile.xml</ProfileName>
  <Pre-selected-indication/>
  <Common index="0">
    <MCPTTUserID entry-info="UsePreConfigured" index="0">
      <uri-entry>%s</uri-entry>
      <display-name xml:lang="en">%s</display-name>
    </MCPTTUserID>
    <UserAlias>
      <alias-entry xml:lang="en" index="0">%s</alias-entry>
    </UserAlias>
    <MissionCriticalOrganization>VectorCore</MissionCriticalOrganization>
    <ParticipantType>MCPTT User</ParticipantType>
    <PrivateCall>
      <PrivateCallList index="0">
        <PrivateCallURI entry-info="UsePreConfigured" index="0">
          <uri-entry>%s</uri-entry>
          <display-name xml:lang="en">%s</display-name>
        </PrivateCallURI>
      </PrivateCallList>
    </PrivateCall>
    <MCPTT-group-call>
      <MaxSimultaneousCallsN6>1</MaxSimultaneousCallsN6>
      <Priority>5</Priority>
    </MCPTT-group-call>
  </Common>
  <OnNetwork index="0">
    <MaxAffiliationsN2>200</MaxAffiliationsN2>
    <MaxSimultaneousTransmissionsN7>1</MaxSimultaneousTransmissionsN7>
    <MCPTTGroupInfo xml:lang="en" index="0">%s
    </MCPTTGroupInfo>
    <ImplicitAffiliations xml:lang="en" index="0">%s
    </ImplicitAffiliations>%s
  </OnNetwork>
</mcptt-user-profile>`,
		xmlText(userURI),
		xmlText(name),
		xmlText(userURI),
		xmlText(displayName),
		xmlText(displayName),
		xmlText(userURI),
		xmlText(displayName),
		groupEntries,
		implicitEntries,
		faList,
	)
}

func gmsGroupURIFromPath(path string) string {
	// TS 24.481 table 7.2.10.2-1: group documents live in the "byGroupID"
	// subdirectory of the global tree. The pre-conformance "byGroup" spelling
	// stays accepted for already-deployed clients.
	for _, marker := range []string{"/global/byGroupID/", "/global/byGroup/"} {
		if idx := strings.Index(path, marker); idx >= 0 {
			groupURI := strings.TrimSpace(path[idx+len(marker):])
			if decoded, err := url.PathUnescape(groupURI); err == nil {
				groupURI = decoded
			}
			return groupURI
		}
	}
	return ""
}

func findGroupByURI(groups []store.Group, uri string) store.Group {
	for _, group := range groups {
		if !group.Enabled {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(group.URI), strings.TrimSpace(uri)) {
			return group
		}
	}
	return store.Group{}
}

func buildGMSMemberEntries(users []store.User, memberships []store.GroupMembership, groupID string) string {
	if groupID == "" {
		return ""
	}
	var b strings.Builder
	for _, membership := range memberships {
		if membership.GroupID != groupID {
			continue
		}
		user := findUserByID(users, membership.UserID)
		userURI := userIdentityURI(user)
		if userURI == "" {
			continue
		}
		displayName := userDisplayName(user)
		if displayName == "" {
			displayName = userURI
		}
		fmt.Fprintf(&b, `
      <entry uri="%s">
        <display-name xml:lang="en">%s</display-name>
        <participant-type>%s</participant-type>
      </entry>`,
			xmlText(userURI),
			xmlText(displayName),
			xmlText(valueOr(membership.Role, "MCPTT User")),
		)
	}
	return b.String()
}

func findUserByID(users []store.User, id string) store.User {
	for _, user := range users {
		if user.ID == id {
			return user
		}
	}
	return store.User{}
}

func findUserByXUI(users []store.User, xui string) store.User {
	xui = strings.TrimSpace(xui)
	if decoded, err := url.PathUnescape(xui); err == nil {
		xui = decoded
	}
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		for _, candidate := range []string{user.ID, user.IMPI, user.IMPU, user.MCPTTID} {
			if strings.EqualFold(strings.TrimSpace(candidate), xui) {
				return user
			}
		}
	}
	return store.User{}
}

func isDefaultProfileXUI(xui string) bool {
	xui = strings.TrimSpace(xui)
	return xui == "" || strings.EqualFold(xui, "default")
}

func etag(body string) string {
	return ContentETag(body)
}

func ContentETag(body string) string {
	sum := sha1.Sum([]byte(body))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func auidFromPath(path string) string {
	path = strings.Trim(path, "/")
	if i := strings.IndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return path
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func xcapUserFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "users" {
			return parts[i+1]
		}
	}
	return ""
}

func userIdentityURI(user store.User) string {
	if strings.TrimSpace(user.IMPU) != "" {
		return strings.TrimSpace(user.IMPU)
	}
	if strings.TrimSpace(user.MCPTTID) != "" {
		return strings.TrimSpace(user.MCPTTID)
	}
	return ""
}

func userDisplayName(user store.User) string {
	if strings.TrimSpace(user.DisplayName) != "" {
		return strings.TrimSpace(user.DisplayName)
	}
	if strings.TrimSpace(user.MCPTTID) != "" {
		return strings.TrimSpace(user.MCPTTID)
	}
	if strings.TrimSpace(user.IMPU) != "" {
		return strings.TrimSpace(user.IMPU)
	}
	return ""
}

func buildGroupEntries(groups []store.Group, memberships []store.GroupMembership, userID string) string {
	var b strings.Builder
	index := 0
	for _, group := range groups {
		if !group.Enabled || strings.TrimSpace(group.URI) == "" {
			continue
		}
		if !hasMembership(memberships, userID, group.ID) {
			continue
		}
		display := strings.TrimSpace(group.DisplayName)
		if display == "" {
			display = group.URI
		}
		fmt.Fprintf(&b, `
      <entry entry-info="LocallyDetermined" index="%d">
        <uri-entry>%s</uri-entry>
        <display-name xml:lang="en">%s</display-name>
      </entry>`, index, xmlText(group.URI), xmlText(display))
		index++
	}
	return b.String()
}

func buildImplicitAffiliationEntries(groups []store.Group, memberships []store.GroupMembership, userID string) string {
	var b strings.Builder
	index := 0
	for _, group := range groups {
		if !group.Enabled || strings.TrimSpace(group.URI) == "" {
			continue
		}
		if !hasMembership(memberships, userID, group.ID) {
			continue
		}
		display := strings.TrimSpace(group.DisplayName)
		if display == "" {
			display = group.URI
		}
		fmt.Fprintf(&b, `
      <entry entry-info="DedicatedGroup" index="%d">
        <uri-entry>%s</uri-entry>
        <display-name xml:lang="en">%s</display-name>
      </entry>`, index, xmlText(group.URI), xmlText(display))
		index++
	}
	return b.String()
}

func buildGroupPriorityEntries(groups []store.Group, memberships []store.GroupMembership, userID string) string {
	var b strings.Builder
	priority := 1
	for _, group := range groups {
		if !group.Enabled || strings.TrimSpace(group.URI) == "" {
			continue
		}
		if !hasMembership(memberships, userID, group.ID) {
			continue
		}
		b.WriteString(groupPriorityEntry(group.URI, priority))
		priority++
	}
	return b.String()
}

func groupPriorityEntry(groupURI string, priority int) string {
	return fmt.Sprintf(`
        <MCPTT-Group-Priority>
          <MCPTT-Group-ID>%s</MCPTT-Group-ID>
          <group-priority-hierarchy>%d</group-priority-hierarchy>
        </MCPTT-Group-Priority>`, xmlText(groupURI), priority)
}

func hasMembership(memberships []store.GroupMembership, userID, groupID string) bool {
	if userID == "" || groupID == "" {
		return false
	}
	for _, membership := range memberships {
		if membership.UserID == userID && membership.GroupID == groupID {
			return true
		}
	}
	return false
}

func xmlText(v string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(v)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logInfo := &xcapRequestInfo{}
		r = r.WithContext(context.WithValue(r.Context(), xcapRequestInfoKey{}, logInfo))
		rr := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(rr, r)

		status := rr.status
		if status == 0 {
			status = http.StatusOK
		}
		reqBytes := r.ContentLength
		if reqBytes < 0 {
			reqBytes = 0
		}
		sourceIP, sourcePort := splitRemoteAddr(r.RemoteAddr)
		xcapPath := xcapPathFromURL(r.URL.Path)
		result := logInfo.result
		if result == "" {
			result = statusResult(status)
		}

		slog.Info("CMS/XCAP request",
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
			"xcap_path", xcapPath,
			"auid", auidFromPath(xcapPath),
			"status", status,
			"result", result,
			"ms", time.Since(start).Milliseconds(),
			"request_bytes", reqBytes,
			"response_bytes", rr.bytes,
			"content_type", r.Header.Get("Content-Type"),
			"user_agent", r.UserAgent(),
			"source_ip", sourceIP,
			"source_port", sourcePort,
		)
	})
}

type xcapRequestInfoKey struct{}

type xcapRequestInfo struct {
	result string
}

func setXCAPResult(r *http.Request, result string) {
	info, ok := r.Context().Value(xcapRequestInfoKey{}).(*xcapRequestInfo)
	if !ok || info == nil {
		return
	}
	info.result = result
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func splitRemoteAddr(remote string) (string, string) {
	host, port, err := net.SplitHostPort(remote)
	if err != nil {
		return remote, ""
	}
	return host, port
}

func xcapPathFromURL(path string) string {
	switch {
	case path == "/xcap-root":
		return "/"
	case strings.HasPrefix(path, "/xcap-root/"):
		xcapPath := strings.TrimPrefix(path, "/xcap-root")
		if xcapPath == "" {
			return "/"
		}
		return xcapPath
	default:
		return ""
	}
}

func statusResult(status int) string {
	switch {
	case status >= 500:
		return "error"
	case status >= 400:
		return "rejected"
	default:
		return "ok"
	}
}

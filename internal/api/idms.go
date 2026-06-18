package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

func registerIDMSShim(mux chi.Router, s *Server) {
	mux.Get("/idms/authorize", s.handleIDMSAuthorize)
	mux.Get("/idms/stats", s.handleIDMSStats)
	mux.Post("/idms/token", s.handleIDMSToken)
}

func (s *Server) handleIDMSAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	target := redirectURI
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	target += separator + "code=vectorcore-dev-code"
	if state := r.URL.Query().Get("state"); state != "" {
		target += "&state=" + state
	}

	slog.Info("IDMS authorize shim",
		"client_id", r.URL.Query().Get("client_id"),
		"redirect_uri", redirectURI,
		"response_type", r.URL.Query().Get("response_type"),
		"source", r.RemoteAddr,
	)
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) handleIDMSStats(w http.ResponseWriter, r *http.Request) {
	slog.Info("IDMS callback shim",
		"has_code", r.URL.Query().Get("code") != "",
		"has_state", r.URL.Query().Get("state") != "",
		"source", r.RemoteAddr,
	)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>VectorCore MCX IdMS</title></head><body style="font-family:sans-serif;margin:2rem"><h1>Authentication complete</h1><p>You can return to the MCPTT client.</p></body></html>`)
}

func (s *Server) handleIDMSToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientID := valueOrAPI(r.Form.Get("client_id"), "mcptt_client")
	mcpttID, mcpttSource, userCount, userErr := s.idmsMCPTTID(r)
	now := time.Now().Unix()
	claims := map[string]string{
		"mcptt_id":  mcpttID,
		"sub":       mcpttID,
		"azp":       clientID,
		"iss":       "vectorcore-mcx-idms",
		"iat":       fmt.Sprint(now),
		"exp":       fmt.Sprint(now + 3600),
		"jti":       fmt.Sprintf("vectorcore-%d", now),
		"client_id": clientID,
	}
	token := unsignedJWT(claims)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  token,
		"id_token":      token,
		"refresh_token": "vectorcore-refresh-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
	})

	slog.Info("IDMS token shim",
		"grant_type", r.Form.Get("grant_type"),
		"client_id", clientID,
		"mcptt_id", mcpttID,
		"identity_source", mcpttSource,
		"user_count", userCount,
		"user_error", userErr,
		"source", r.RemoteAddr,
	)
}

func (s *Server) idmsMCPTTID(r *http.Request) (string, string, int, string) {
	// Try to identify the device by its source IP, populated from SIP SUBSCRIBE
	// Contact headers after the first successful registration cycle.
	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if sourceIP != "" {
		if mcpttID, err := s.st.GetMCPTTIDByUEIP(r.Context(), sourceIP); err == nil && mcpttID != "" {
			users, _ := s.st.ListUsers(r.Context())
			return mcpttID, "ue_contact_ip", len(users), ""
		}
	}

	// Fall back: return the first enabled user with a populated identity.
	// On a device's very first boot the IP→user mapping does not exist yet;
	// the mapping is built the moment the device sends its first SIP SUBSCRIBE,
	// so subsequent connections (after an app restart) resolve correctly.
	users, err := s.st.ListUsers(r.Context())
	if err == nil {
		for _, user := range users {
			if !user.Enabled {
				continue
			}
			if strings.TrimSpace(user.IMPU) != "" {
				return strings.TrimSpace(user.IMPU), "users.impu", len(users), ""
			}
			if strings.TrimSpace(user.MCPTTID) != "" {
				return strings.TrimSpace(user.MCPTTID), "users.mcptt_id", len(users), ""
			}
		}
	}
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	return valueOrAPI(s.cfg.MCX.DefaultUserIdentity, "sip:mcptt-user@"+s.cfg.IMS.Realm), "fallback", len(users), errText
}

func unsignedJWT(claims map[string]string) string {
	header := map[string]string{"alg": "none", "typ": "JWT"}
	return base64.RawURLEncoding.EncodeToString(mustJSON(header)) + "." +
		base64.RawURLEncoding.EncodeToString(mustJSON(claims)) + "."
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func valueOrAPI(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

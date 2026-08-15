// Package api implements the VectorCore MCX REST API and web UI server.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/mctoken"
	"github.com/svinson1121/vectorcore-mcx/internal/store"
	"github.com/svinson1121/vectorcore-mcx/internal/tlsutil"
)

type Server struct {
	st         store.Store
	cfg        config.Config
	version    string
	startAt    time.Time
	idmsSigner *idmsSigner
	oidc       *oidcState
	// partnerIdMS validates the security tokens of partner MC domains,
	// keyed by their issuer (TS 33.180 clause B.7.4).
	partnerIdMS map[string]*mctoken.Validator
}

func New(st store.Store, cfg config.Config, version string) *Server {
	s := &Server{st: st, cfg: cfg, version: version, startAt: time.Now(), oidc: newOIDCState()}
	if cfg.IDMS.DevelopmentShimEnabled || cfg.IDMS.Enabled {
		signer, err := newIDMSSigner(cfg.IDMS.SigningKeyFile)
		if err != nil {
			// The shim was asked for but cannot sign. Leaving the signer nil
			// makes its endpoints fail closed rather than fall back to an
			// unsigned token, which TS 33.180 Annex B.2.2.1 forbids.
			slog.Error("IDMS development shim enabled but signing key unavailable; token endpoint will refuse requests", "err", err)
		} else {
			s.idmsSigner = signer
		}
		s.partnerIdMS = loadPartnerIdMS(cfg.IDMS.Partners)
	}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := chi.NewRouter()
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.RealIP)
	mux.Use(requestLogger)

	humaConfig := huma.DefaultConfig("VectorCore MCX API", s.version)
	humaConfig.OpenAPIPath = "/api/v1/openapi.json"
	humaConfig.DocsPath = "/api/v1/docs"
	humaConfig.SchemasPath = "/api/v1/schemas"
	humaConfig.Info.Description = "OAM REST API for the VectorCore MCX Application Server"
	api := humachi.New(mux, humaConfig)

	registerStatus(api, s)
	registerUsers(api, s.st)
	registerGroups(api, s.st)
	registerMemberships(api, s.st)
	registerGroupAffiliations(api, s.st)
	registerRegistrations(api, s.st)
	registerCalls(api, s.st)
	registerDialogs(api, s.st)

	// The conformant IdMS (TS 33.180 Annex B) takes precedence; the
	// development shim - which authenticates nobody - registers only when it
	// alone is enabled. When neither is enabled the paths do not exist at
	// all rather than returning an error, so there is nothing to probe.
	switch {
	case s.cfg.IDMS.Enabled:
		registerIDMSOIDC(mux, s)
	case s.cfg.IDMS.DevelopmentShimEnabled:
		slog.Warn("IDMS development shim enabled: it performs NO user authentication and must not be reachable from an untrusted network")
		registerIDMSShim(mux, s)
	}

	mux.Handle("/metrics", promhttp.Handler())
	mux.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	mux.Handle("/ui", http.RedirectHandler("/ui/", http.StatusMovedPermanently))
	ui := uiHandler()
	mux.Handle("/ui/", ui)
	mux.Handle("/ui/*", ui)
	mux.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	return mux
}

func (s *Server) Start(ctx context.Context, addr string) error {
	tlsConf, err := tlsutil.ServerConfig(s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("api listener: %w", err)
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.Handler(),
		TLSConfig:    tlsConf,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		serve := srv.ListenAndServe
		if tlsConf != nil {
			// Certificates already live in TLSConfig, so the file arguments
			// stay empty.
			serve = func() error { return srv.ListenAndServeTLS("", "") }
		}
		slog.Info("API server listening", "addr", addr, "tls", tlsConf != nil)
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

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		slog.Debug("api",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"ms", time.Since(start).Milliseconds(),
		)
	})
}

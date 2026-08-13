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
	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

type Server struct {
	st         store.Store
	cfg        config.Config
	version    string
	startAt    time.Time
	idmsSigner *idmsSigner
}

func New(st store.Store, cfg config.Config, version string) *Server {
	s := &Server{st: st, cfg: cfg, version: version, startAt: time.Now()}
	if cfg.IDMS.DevelopmentShimEnabled {
		signer, err := newIDMSSigner(cfg.IDMS.SigningKeyFile)
		if err != nil {
			// The shim was asked for but cannot sign. Leaving the signer nil
			// makes its endpoints fail closed rather than fall back to an
			// unsigned token, which TS 33.180 Annex B.2.2.1 forbids.
			slog.Error("IDMS development shim enabled but signing key unavailable; token endpoint will refuse requests", "err", err)
		} else {
			s.idmsSigner = signer
		}
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

	// The development identity shim authenticates nobody, so it is registered
	// only when explicitly enabled. When disabled its paths do not exist at
	// all rather than returning an error, so there is nothing to probe.
	if s.cfg.IDMS.DevelopmentShimEnabled {
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
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("API server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

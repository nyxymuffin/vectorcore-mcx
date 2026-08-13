package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/svinson1121/vectorcore-mcx/internal/api"
	"github.com/svinson1121/vectorcore-mcx/internal/cms"
	"github.com/svinson1121/vectorcore-mcx/internal/config"
	"github.com/svinson1121/vectorcore-mcx/internal/media"
	sipserver "github.com/svinson1121/vectorcore-mcx/internal/sip"
	"github.com/svinson1121/vectorcore-mcx/internal/store/sqlite"
)

var version = "dev"

func main() {
	configPath := flag.String("c", "config.yaml", "path to YAML configuration")
	debug := flag.Bool("d", false, "enable debug console logging")
	showVersion := flag.Bool("v", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("VectorCore MCX %s\n", version)
		os.Exit(0)
	}
	var logFile, logLevel string
	if earlycfg, err := config.Load(*configPath); err == nil {
		logFile = earlycfg.Log.File
		logLevel = earlycfg.Log.Level
	}
	closer := setupLogging(*debug, logFile, logLevel)
	if closer != nil {
		defer closer()
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	if cfg.UsedDefaults {
		slog.Warn("configuration file not found, using built-in defaults",
			"path", *configPath, "advertise_host", cfg.SIP.AdvertiseHost, "realm", cfg.IMS.Realm)
	}

	st, err := openStore(cfg)
	if err != nil {
		slog.Error("open database", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 8)
	sipSrv := sipserver.NewServer(cfg, st)
	go func() { errCh <- api.New(st, cfg, version).Start(ctx, cfg.API.Listen) }()
	go func() { errCh <- cms.NewServer(cfg, st).Start(ctx) }()
	go func() { errCh <- media.NewObserver(cfg, st).Start(ctx) }()
	go func() { errCh <- sipSrv.ListenUDP(ctx) }()
	go func() { errCh <- sipSrv.ListenTCP(ctx) }()
	go func() { errCh <- sipSrv.ListenTLS(ctx) }()
	go func() { errCh <- sipSrv.StartOptions(ctx) }()
	go func() { errCh <- sipSrv.StartTransactionReaper(ctx) }()
	go startRegistrationExpiry(ctx, st)

	slog.Info("VectorCore MCX started", "version", version, "config", *configPath, "database_driver", cfg.Database.Driver)

	if err := <-errCh; err != nil && ctx.Err() == nil {
		slog.Error("mcxas stopped", "err", err)
		os.Exit(1)
	}
}

func startRegistrationExpiry(ctx context.Context, st interface {
	ExpireRegistrations(context.Context, time.Time) (int, error)
}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := st.ExpireRegistrations(ctx, time.Now().UTC())
			if err != nil {
				slog.Warn("registration expiry failed", "err", err)
				continue
			}
			if n > 0 {
				slog.Info("MCPTT registrations expired", "count", n)
			}
		}
	}
}

func openStore(cfg config.Config) (*sqlite.Store, error) {
	switch strings.ToLower(cfg.Database.Driver) {
	case "", "sqlite":
		return sqlite.Open(cfg.Database.DSN)
	case "postgres", "postgresql":
		return sqlite.OpenPostgres(cfg.Database.DSN)
	default:
		return nil, fmt.Errorf("unsupported database driver: %q", cfg.Database.Driver)
	}
}

func setupLogging(debug bool, logFile, logLevel string) (closer func()) {
	level := slog.LevelInfo
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	if debug {
		level = slog.LevelDebug
	}

	var w io.Writer = os.Stderr
	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err == nil {
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				w = io.MultiWriter(os.Stderr, f)
				closer = func() { _ = f.Close() }
			} else {
				fmt.Fprintf(os.Stderr, "warning: cannot open log file %q: %v\n", logFile, err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "warning: cannot create log dir for %q: %v\n", logFile, err)
		}
	}

	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
	return closer
}

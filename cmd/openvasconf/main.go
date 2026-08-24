package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"

	"openvasconf/internal/auth"
	"openvasconf/internal/config"
	"openvasconf/internal/gmp"
	"openvasconf/internal/reconcile"
	"openvasconf/internal/report"
	"openvasconf/internal/store"
	"openvasconf/internal/updater"
	"openvasconf/internal/web"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && os.Args[1] == "validate-config" {
		os.Exit(validateConfig(os.Stdout))
	}
	if err := run(logger); err != nil {
		logger.Error("openvasconf stopped", "error", err)
		os.Exit(1)
	}
}

// validateConfig loads the same configuration and secret references as normal
// startup and reports every discovered validation problem without starting the
// HTTP server or connecting to the database or Greenbone. Secret values are
// never printed; failures name the setting instead.
func validateConfig(out io.Writer) int {
	problems := config.LoadDetailed()
	if len(problems) == 0 {
		_, _ = fmt.Fprintln(out, "configuration valid")
		return 0
	}
	for _, problem := range problems {
		_, _ = fmt.Fprintf(out, "configuration invalid: %s\n", problem)
	}
	return 1
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	repository, err := store.Open(ctx, cfg.DatabasePath, cfg.Timezone)
	if err != nil {
		return fmt.Errorf("opening repository: %w", err)
	}
	defer func() {
		if closeErr := repository.Close(); closeErr != nil {
			logger.Error("closing repository", "error", closeErr)
		}
	}()

	authenticator := auth.New(repository, cfg.SessionLifetime)
	if err := authenticator.Bootstrap(ctx, cfg.AdminPassword); err != nil {
		return fmt.Errorf("bootstrapping authentication: %w", err)
	}

	greenbone := gmp.New(
		cfg.GMPSocketPath,
		cfg.GMPUsername,
		cfg.GMPPassword,
		cfg.ExternalTimeout,
	)
	updateClient := updater.NewClient(cfg.UpdaterSocketPath, cfg.ExternalTimeout)
	updatePolicy, policyErr := repository.UpdatePolicy(ctx)
	if policyErr != nil {
		return fmt.Errorf("loading updater policy: %w", policyErr)
	}
	if err := updateClient.Configure(ctx, updatePolicy); err != nil {
		logger.Warn("updater helper unavailable during startup", "error", err)
	}
	syncer := reconcile.New(repository, greenbone, logger, cfg.ReconcileEvery)
	reportSyncer := report.NewSyncer(
		repository,
		greenbone,
		logger,
		cfg.ReportSyncInterval,
		report.Limits{
			MaxFindings: cfg.ReportMaxFindings,
			MaxXMLBytes: cfg.ReportMaxXMLBytes,
			Concurrency: cfg.ReportImportConcurrency,
		},
	)
	webServer, err := web.New(web.Options{
		Repository:          repository,
		Auth:                authenticator,
		Greenbone:           greenbone,
		Syncer:              syncer,
		Reports:             reportSyncer,
		Updater:             updateClient,
		Logger:              logger,
		SecureCookies:       cfg.SecureCookies,
		TrustProxyTLSHeader: cfg.TrustProxyTLSHeader,
		ExportMaxRows:       cfg.ExportMaxRows,
		ExportMaxBytes:      cfg.ExportMaxBytes,
	})
	if err != nil {
		return fmt.Errorf("creating web server: %w", err)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           webServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go syncer.Run(ctx)
	go reportSyncer.Run(ctx)
	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("web server listening", "address", cfg.ListenAddress)
		serveErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case serveErr := <-serveErrors:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serving HTTP: %w", serveErr)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down HTTP server: %w", err)
	}
	return nil
}

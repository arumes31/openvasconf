package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"openvasconf/internal/gmp"
	"openvasconf/internal/updater"
)

const (
	defaultSocketPath  = "/run/openvasconf-updater/updater.sock"
	defaultStatePath   = "/state/updater.json"
	defaultBackupDir   = "/backups"
	defaultComposeFile = "/deployment/greenbone-compose.yaml"
	defaultProject     = "greenbone-community-edition"
	defaultGMPSocket   = "/run/gvmd/gvmd.sock"
	defaultGMPUsername = "admin"
	defaultTimezone    = "Europe/Vienna"
)

type helperConfig struct {
	SocketPath  string
	StatePath   string
	BackupDir   string
	ComposeFile string
	Project     string
	GMPSocket   string
	GMPUsername string
	GMPPassword string
	Timezone    string
	Timeout     time.Duration
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("openvasconf updater stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	compose, err := updater.NewCompose(
		updater.OSCommandExecutor{}, config.ComposeFile, config.Project, config.BackupDir,
	)
	if err != nil {
		return err
	}
	stateStore, err := updater.NewFileStateStore(config.StatePath)
	if err != nil {
		return err
	}
	greenbone := gmp.New(
		config.GMPSocket, config.GMPUsername, config.GMPPassword, config.Timeout,
	)
	controller, err := updater.NewController(updater.ControllerOptions{
		Runtime:       compose,
		Scanner:       gmpScanner{client: greenbone},
		Store:         stateStore,
		Logger:        logger,
		DefaultPolicy: updater.DefaultPolicy(config.Timezone),
	})
	if err != nil {
		return err
	}
	if err := controller.Start(ctx); err != nil {
		return err
	}
	defer controller.Close()
	handler, err := updater.NewHandler(controller)
	if err != nil {
		return err
	}
	listener, err := listenUnix(config.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(config.SocketPath)
	}()

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("updater helper listening", "socket", config.SocketPath)
		serveErrors <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
	case serveErr := <-serveErrors:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serving updater API: %w", serveErr)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down updater API: %w", err)
	}
	return nil
}

type gmpScanner struct {
	client *gmp.Client
}

func (s gmpScanner) Ping(ctx context.Context) error {
	_, err := s.client.Ping(ctx)
	return err
}

func (s gmpScanner) Feeds(ctx context.Context) ([]updater.Feed, error) {
	feeds, err := s.client.Feeds(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]updater.Feed, 0, len(feeds))
	for _, feed := range feeds {
		result = append(result, updater.Feed{
			Name:             feed.Name,
			Version:          feed.Version,
			CurrentlySyncing: feed.CurrentlySyncing,
			UpdatedAt:        feed.UpdatedAt,
		})
	}
	return result, nil
}

func (s gmpScanner) ActiveScans(ctx context.Context) (int, error) {
	tasks, err := s.client.Tasks(ctx)
	if err != nil {
		return 0, err
	}
	active := 0
	for _, task := range tasks {
		if scanIsActive(task.Status) {
			active++
		}
	}
	return active, nil
}

func scanIsActive(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "requested", "queued", "processing", "stop requested", "resume requested":
		return true
	default:
		return false
	}
}

func loadConfig() (helperConfig, error) {
	password, err := secret("OPENVASCONF_GMP_PASSWORD", "OPENVASCONF_GMP_PASSWORD_FILE")
	if err != nil {
		return helperConfig{}, fmt.Errorf("loading GMP password: %w", err)
	}
	timeout := 15 * time.Second
	if raw := strings.TrimSpace(os.Getenv("OPENVASCONF_UPDATER_TIMEOUT")); raw != "" {
		timeout, err = time.ParseDuration(raw)
		if err != nil || timeout <= 0 {
			return helperConfig{}, errors.New("OPENVASCONF_UPDATER_TIMEOUT must be a positive duration")
		}
	}
	config := helperConfig{
		SocketPath:  envValue("OPENVASCONF_UPDATER_SOCKET", defaultSocketPath),
		StatePath:   envValue("OPENVASCONF_UPDATER_STATE", defaultStatePath),
		BackupDir:   envValue("OPENVASCONF_UPDATER_BACKUPS", defaultBackupDir),
		ComposeFile: envValue("OPENVASCONF_UPDATER_COMPOSE_FILE", defaultComposeFile),
		Project:     envValue("OPENVASCONF_UPDATER_PROJECT", defaultProject),
		GMPSocket:   envValue("OPENVASCONF_GMP_SOCKET", defaultGMPSocket),
		GMPUsername: envValue("OPENVASCONF_GMP_USERNAME", defaultGMPUsername),
		GMPPassword: password,
		Timezone:    envValue("OPENVASCONF_TIMEZONE", defaultTimezone),
		Timeout:     timeout,
	}
	for name, path := range map[string]string{
		"OPENVASCONF_UPDATER_SOCKET":       config.SocketPath,
		"OPENVASCONF_UPDATER_STATE":        config.StatePath,
		"OPENVASCONF_UPDATER_BACKUPS":      config.BackupDir,
		"OPENVASCONF_UPDATER_COMPOSE_FILE": config.ComposeFile,
		"OPENVASCONF_GMP_SOCKET":           config.GMPSocket,
	} {
		if !filepath.IsAbs(path) {
			return helperConfig{}, fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if _, err := time.LoadLocation(config.Timezone); err != nil {
		return helperConfig{}, fmt.Errorf("invalid OPENVASCONF_TIMEZONE: %w", err)
	}
	return config, nil
}

func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("creating updater socket directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&fs.ModeSocket == 0 {
			return nil, errors.New("updater socket path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing stale updater socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("checking updater socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on updater socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restricting updater socket: %w", err)
	}
	return listener, nil
}

func secret(valueKey, fileKey string) (string, error) {
	if path := strings.TrimSpace(os.Getenv(fileKey)); path != "" {
		// #nosec G304,G703 -- the deployment explicitly supplies this secret-file path.
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", fileKey, err)
		}
		return strings.TrimSpace(string(contents)), nil
	}
	return os.Getenv(valueKey), nil
}

func envValue(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

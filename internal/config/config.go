package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddress   = "127.0.0.1:8080"
	defaultDatabasePath    = "data/openvasconf.db"
	defaultGMPSocketPath   = "/run/gvmd/gvmd.sock"
	defaultGMPUsername     = "admin"
	defaultTimezone        = "Europe/Vienna"
	defaultReconcileEvery  = time.Minute
	defaultExternalTimeout = 15 * time.Second
	defaultSessionLifetime = 12 * time.Hour
	adminSecretValueEnv    = "OPENVASCONF_ADMIN_" + "PASSWORD"
)

type Config struct {
	ListenAddress       string
	DatabasePath        string
	GMPSocketPath       string
	GMPUsername         string
	GMPPassword         string
	AdminPassword       string
	Timezone            string
	ReconcileEvery      time.Duration
	ExternalTimeout     time.Duration
	SessionLifetime     time.Duration
	SecureCookies       bool
	TrustProxyTLSHeader bool
}

func Load() (Config, error) {
	gmpPassword, err := secret("OPENVASCONF_GMP_PASSWORD", "OPENVASCONF_GMP_PASSWORD_FILE")
	if err != nil {
		return Config{}, fmt.Errorf("loading gmp password: %w", err)
	}

	adminPassword, err := secret(adminSecretValueEnv, "OPENVASCONF_ADMIN_PASSWORD_FILE")
	if err != nil {
		return Config{}, fmt.Errorf("loading admin password: %w", err)
	}

	reconcileEvery, err := duration("OPENVASCONF_RECONCILE_INTERVAL", defaultReconcileEvery)
	if err != nil {
		return Config{}, err
	}

	externalTimeout, err := duration("OPENVASCONF_EXTERNAL_TIMEOUT", defaultExternalTimeout)
	if err != nil {
		return Config{}, err
	}

	sessionLifetime, err := duration("OPENVASCONF_SESSION_LIFETIME", defaultSessionLifetime)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		ListenAddress:       value("OPENVASCONF_LISTEN", defaultListenAddress),
		DatabasePath:        value("OPENVASCONF_DATABASE", defaultDatabasePath),
		GMPSocketPath:       value("OPENVASCONF_GMP_SOCKET", defaultGMPSocketPath),
		GMPUsername:         value("OPENVASCONF_GMP_USERNAME", defaultGMPUsername),
		GMPPassword:         gmpPassword,
		AdminPassword:       adminPassword,
		Timezone:            value("OPENVASCONF_TIMEZONE", defaultTimezone),
		ReconcileEvery:      reconcileEvery,
		ExternalTimeout:     externalTimeout,
		SessionLifetime:     sessionLifetime,
		SecureCookies:       boolean("OPENVASCONF_SECURE_COOKIES", false),
		TrustProxyTLSHeader: boolean("OPENVASCONF_TRUST_PROXY_TLS", false),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" {
		return errors.New("config: listen address is required")
	}
	if strings.TrimSpace(c.DatabasePath) == "" {
		return errors.New("config: database path is required")
	}
	if strings.TrimSpace(c.GMPSocketPath) == "" {
		return errors.New("config: gmp socket path is required")
	}
	if strings.TrimSpace(c.GMPUsername) == "" {
		return errors.New("config: gmp username is required")
	}
	if c.AdminPassword == "" {
		return errors.New("config: admin password is required")
	}
	if len(c.AdminPassword) < 12 {
		return errors.New("config: admin password must contain at least 12 characters")
	}
	if c.ReconcileEvery <= 0 || c.ExternalTimeout <= 0 || c.SessionLifetime <= 0 {
		return errors.New("config: durations must be positive")
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("config: invalid timezone %q: %w", c.Timezone, err)
	}
	return nil
}

func secret(valueKey, fileKey string) (string, error) {
	if path := strings.TrimSpace(os.Getenv(fileKey)); path != "" {
		// #nosec G304,G703 -- the operator explicitly supplies this local secret-file path.
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", fileKey, err)
		}
		return strings.TrimSpace(string(contents)), nil
	}
	return os.Getenv(valueKey), nil
}

func duration(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: parsing %s: %w", key, err)
	}
	return parsed, nil
}

func value(key, fallback string) string {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		return raw
	}
	return fallback
}

func boolean(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

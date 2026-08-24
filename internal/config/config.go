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
	defaultListenAddress          = "127.0.0.1:8080"
	defaultDatabasePath           = "data/openvasconf.db"
	defaultGMPSocketPath          = "/run/gvmd/gvmd.sock"
	defaultUpdaterSocketPath      = "/run/openvasconf-updater/updater.sock"
	defaultGMPUsername            = "admin"
	defaultTimezone               = "Europe/Vienna"
	defaultReconcileEvery         = time.Minute
	defaultExternalTimeout        = 15 * time.Second
	defaultSessionLifetime        = 12 * time.Hour
	defaultReportSyncEvery        = 2 * time.Minute
	defaultReportMaxXMLBytes      = 64 << 20
	defaultReportMaxFindings      = 50000
	defaultReportImportConcurrent = 1
	defaultExportMaxRows          = 100000
	defaultExportMaxBytes         = 50 << 20
	adminSecretValueEnv           = "OPENVASCONF_ADMIN_" + "PASSWORD"
)

type Config struct {
	ListenAddress           string
	DatabasePath            string
	GMPSocketPath           string
	UpdaterSocketPath       string
	GMPUsername             string
	GMPPassword             string
	AdminPassword           string
	Timezone                string
	ReconcileEvery          time.Duration
	ExternalTimeout         time.Duration
	SessionLifetime         time.Duration
	ReportSyncInterval      time.Duration
	ReportMaxXMLBytes       int64
	ReportMaxFindings       int
	ReportImportConcurrency int
	ExportMaxRows           int
	ExportMaxBytes          int64
	SecureCookies           bool
	TrustProxyTLSHeader     bool
}

func Load() (Config, error) {
	cfg, problems := load()
	if len(problems) > 0 {
		return Config{}, errors.Join(problems...)
	}
	return cfg, nil
}

// LoadDetailed loads the same configuration and secret references as Load but
// reports every discovered validation problem instead of the first one. It is
// used by the validate-config command and never prints secret values.
func LoadDetailed() []error {
	_, problems := load()
	return problems
}

func load() (Config, []error) {
	problems := make([]error, 0)

	gmpPassword, err := secret("OPENVASCONF_GMP_PASSWORD", "OPENVASCONF_GMP_PASSWORD_FILE")
	if err != nil {
		problems = append(problems, fmt.Errorf("loading gmp password: %w", err))
	}

	adminPassword, err := secret(adminSecretValueEnv, "OPENVASCONF_ADMIN_PASSWORD_FILE")
	if err != nil {
		problems = append(problems, fmt.Errorf("loading admin password: %w", err))
	}

	reconcileEvery, err := duration("OPENVASCONF_RECONCILE_INTERVAL", defaultReconcileEvery)
	if err != nil {
		problems = append(problems, err)
	}

	externalTimeout, err := duration("OPENVASCONF_EXTERNAL_TIMEOUT", defaultExternalTimeout)
	if err != nil {
		problems = append(problems, err)
	}

	sessionLifetime, err := duration("OPENVASCONF_SESSION_LIFETIME", defaultSessionLifetime)
	if err != nil {
		problems = append(problems, err)
	}

	reportSyncInterval, err := duration("OPENVASCONF_REPORT_SYNC_INTERVAL", defaultReportSyncEvery)
	if err != nil {
		problems = append(problems, err)
	}

	reportMaxXMLBytes, err := integer("OPENVASCONF_REPORT_MAX_XML_BYTES", defaultReportMaxXMLBytes)
	if err != nil {
		problems = append(problems, err)
	}

	reportMaxFindings, err := nativeInteger("OPENVASCONF_REPORT_MAX_FINDINGS", defaultReportMaxFindings)
	if err != nil {
		problems = append(problems, err)
	}

	reportImportConcurrency, err := nativeInteger(
		"OPENVASCONF_REPORT_IMPORT_CONCURRENCY",
		defaultReportImportConcurrent,
	)
	if err != nil {
		problems = append(problems, err)
	}

	exportMaxRows, err := nativeInteger("OPENVASCONF_EXPORT_MAX_ROWS", defaultExportMaxRows)
	if err != nil {
		problems = append(problems, err)
	}

	exportMaxBytes, err := integer("OPENVASCONF_EXPORT_MAX_BYTES", defaultExportMaxBytes)
	if err != nil {
		problems = append(problems, err)
	}

	secureCookies, err := boolean("OPENVASCONF_SECURE_COOKIES", false)
	if err != nil {
		problems = append(problems, err)
	}

	trustProxyTLS, err := boolean("OPENVASCONF_TRUST_PROXY_TLS", false)
	if err != nil {
		problems = append(problems, err)
	}

	cfg := Config{
		ListenAddress:           value("OPENVASCONF_LISTEN", defaultListenAddress),
		DatabasePath:            value("OPENVASCONF_DATABASE", defaultDatabasePath),
		GMPSocketPath:           value("OPENVASCONF_GMP_SOCKET", defaultGMPSocketPath),
		UpdaterSocketPath:       value("OPENVASCONF_UPDATER_SOCKET", defaultUpdaterSocketPath),
		GMPUsername:             value("OPENVASCONF_GMP_USERNAME", defaultGMPUsername),
		GMPPassword:             gmpPassword,
		AdminPassword:           adminPassword,
		Timezone:                value("OPENVASCONF_TIMEZONE", defaultTimezone),
		ReconcileEvery:          reconcileEvery,
		ExternalTimeout:         externalTimeout,
		SessionLifetime:         sessionLifetime,
		ReportSyncInterval:      reportSyncInterval,
		ReportMaxXMLBytes:       reportMaxXMLBytes,
		ReportMaxFindings:       reportMaxFindings,
		ReportImportConcurrency: reportImportConcurrency,
		ExportMaxRows:           exportMaxRows,
		ExportMaxBytes:          exportMaxBytes,
		SecureCookies:           secureCookies,
		TrustProxyTLSHeader:     trustProxyTLS,
	}

	return cfg, append(problems, cfg.validate()...)
}

func (c Config) Validate() error {
	return errors.Join(c.validate()...)
}

func (c Config) validate() []error {
	problems := make([]error, 0)
	if strings.TrimSpace(c.ListenAddress) == "" {
		problems = append(problems, errors.New("config: OPENVASCONF_LISTEN listen address is required"))
	}
	if strings.TrimSpace(c.DatabasePath) == "" {
		problems = append(problems, errors.New("config: OPENVASCONF_DATABASE database path is required"))
	}
	if strings.TrimSpace(c.GMPSocketPath) == "" {
		problems = append(problems, errors.New("config: OPENVASCONF_GMP_SOCKET gmp socket path is required"))
	}
	if strings.TrimSpace(c.UpdaterSocketPath) == "" {
		problems = append(problems, errors.New("config: OPENVASCONF_UPDATER_SOCKET updater socket path is required"))
	}
	if strings.TrimSpace(c.GMPUsername) == "" {
		problems = append(problems, errors.New("config: OPENVASCONF_GMP_USERNAME gmp username is required"))
	}
	if c.AdminPassword == "" {
		problems = append(problems, errors.New("config: admin password is required (OPENVASCONF_ADMIN_PASSWORD or OPENVASCONF_ADMIN_PASSWORD_FILE)"))
	} else if len(c.AdminPassword) < 12 {
		problems = append(problems, errors.New("config: admin password must contain at least 12 characters"))
	}
	if c.ReconcileEvery <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_RECONCILE_INTERVAL must be positive"))
	}
	if c.ExternalTimeout <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_EXTERNAL_TIMEOUT must be positive"))
	}
	if c.SessionLifetime <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_SESSION_LIFETIME must be positive"))
	}
	if c.ReportSyncInterval <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_REPORT_SYNC_INTERVAL must be positive"))
	}
	if c.ReportMaxXMLBytes <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_REPORT_MAX_XML_BYTES must be positive"))
	}
	if c.ReportMaxFindings <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_REPORT_MAX_FINDINGS must be positive"))
	}
	if c.ReportImportConcurrency <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_REPORT_IMPORT_CONCURRENCY must be positive"))
	}
	if c.ExportMaxRows <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_EXPORT_MAX_ROWS must be positive"))
	}
	if c.ExportMaxBytes <= 0 {
		problems = append(problems, errors.New("config: OPENVASCONF_EXPORT_MAX_BYTES must be positive"))
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		problems = append(problems, fmt.Errorf("config: invalid OPENVASCONF_TIMEZONE %q: %w", c.Timezone, err))
	}
	return problems
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

func integer(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: parsing %s: %w", key, err)
	}
	return parsed, nil
}

func nativeInteger(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
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

func boolean(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: parsing %s: %w", key, err)
	}
	return parsed, nil
}

// Package hookwise delivers task-scoped finding lifecycle events through a
// durable, bearer-authenticated webhook outbox.
package hookwise

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/store"
)

const (
	dispatchInterval = 30 * time.Second
	responseLimit    = 4096
)

// Repository is the persistence boundary required by the dispatcher.
type Repository interface {
	Settings(ctx context.Context) (customer.Settings, error)
	UpdateHookwiseSettings(ctx context.Context, settings customer.HookwiseSettings) error
	ReconcileHookwiseOutbox(ctx context.Context) error
	PendingHookwiseEvents(ctx context.Context, limit int) ([]store.HookwiseEvent, error)
	MarkHookwiseDelivered(ctx context.Context, event store.HookwiseEvent, status int) error
	MarkHookwiseFailed(ctx context.Context, event store.HookwiseEvent, status int, diagnostic string) error
	RetryHookwiseEvents(ctx context.Context) error
	HookwiseStats(ctx context.Context) (store.HookwiseStats, error)
	AddAuditEvent(ctx context.Context, event store.AuditEvent) error
}

// Manager owns encrypted configuration and the durable outbox dispatcher.
type Manager struct {
	repository Repository
	key        []byte
	client     *http.Client
	logger     *slog.Logger
	trigger    chan struct{}
}

// New constructs a manager. A missing key is allowed while integration is
// disabled; enabling or decrypting configuration then fails closed.
func New(repository Repository, key []byte, timeout time.Duration, logger *slog.Logger) *Manager {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Manager{
		repository: repository,
		key:        append([]byte(nil), key...),
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger:  logger,
		trigger: make(chan struct{}, 1),
	}
}

// Trigger requests an out-of-band reconciliation and delivery pass.
func (m *Manager) Trigger() {
	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

// Run dispatches immediately and periodically until ctx is canceled.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(dispatchInterval)
	defer ticker.Stop()
	m.run(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.run(ctx)
		case <-m.trigger:
			m.run(ctx)
		}
	}
}

func (m *Manager) run(ctx context.Context) {
	if err := m.DispatchOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		m.logger.Error("hookwise dispatch failed", "error", err)
	}
}

// DispatchOnce reconciles desired tickets and delivers one bounded batch.
func (m *Manager) DispatchOnce(ctx context.Context) error {
	settings, err := m.repository.Settings(ctx)
	if err != nil {
		return fmt.Errorf("hookwise: loading settings: %w", err)
	}
	if !settings.Hookwise.Enabled {
		return nil
	}
	token, err := m.decrypt(settings.Hookwise.TokenCipher)
	if err != nil {
		return fmt.Errorf("hookwise: decrypting token: %w", err)
	}
	if err := validateEndpoint(settings.Hookwise.Endpoint); err != nil {
		return err
	}
	if err := m.repository.ReconcileHookwiseOutbox(ctx); err != nil {
		return fmt.Errorf("hookwise: reconciling tickets: %w", err)
	}
	events, err := m.repository.PendingHookwiseEvents(ctx, 20)
	if err != nil {
		return fmt.Errorf("hookwise: loading outbox: %w", err)
	}
	for _, event := range events {
		status, sendErr := m.send(ctx, settings.Hookwise.Endpoint, token, event.Payload)
		if sendErr != nil {
			if markErr := m.repository.MarkHookwiseFailed(ctx, event, status, sendErr.Error()); markErr != nil {
				return errors.Join(sendErr, markErr)
			}
			continue
		}
		if err := m.repository.MarkHookwiseDelivered(ctx, event, status); err != nil {
			return err
		}
		if err := m.repository.AddAuditEvent(ctx, store.AuditEvent{
			CustomerID:   event.CustomerID,
			Action:       "hookwise_" + event.EventType,
			ResourceKind: "finding",
			ResourceName: event.Fingerprint,
			Detail:       fmt.Sprintf("generation %d delivered", event.Generation),
		}); err != nil {
			m.logger.Warn("hookwise audit event failed", "error", err)
		}
	}
	return nil
}

// Save validates and encrypts global integration settings. An empty token
// preserves the current write-only credential.
func (m *Manager) Save(
	ctx context.Context,
	enabled bool,
	endpoint,
	token string,
) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint != "" {
		if err := validateEndpoint(endpoint); err != nil {
			return err
		}
	}
	current, err := m.repository.Settings(ctx)
	if err != nil {
		return err
	}
	config := current.Hookwise
	config.Enabled = enabled
	config.Endpoint = endpoint
	if token = strings.TrimSpace(token); token != "" {
		config.TokenCipher, err = m.encrypt(token)
		if err != nil {
			return err
		}
	}
	if enabled && (config.Endpoint == "" || config.TokenCipher == "") {
		return errors.New("hookwise endpoint and bearer token are required when enabled")
	}
	if enabled && len(m.key) != 32 {
		return errors.New("hookwise encryption key is not configured in the deployment")
	}
	if err := m.repository.UpdateHookwiseSettings(ctx, config); err != nil {
		return err
	}
	if err := m.repository.AddAuditEvent(ctx, store.AuditEvent{
		Action: "hookwise_settings_updated", ResourceKind: "settings",
		Detail: fmt.Sprintf("enabled=%t endpoint_configured=%t token_replaced=%t", enabled, endpoint != "", token != ""),
	}); err != nil {
		m.logger.Warn("hookwise settings audit failed", "error", err)
	}
	m.Trigger()
	return nil
}

// Test sends a connection_test state that does not match open/close triggers.
func (m *Manager) Test(ctx context.Context) error {
	settings, err := m.repository.Settings(ctx)
	if err != nil {
		return err
	}
	if err := validateEndpoint(settings.Hookwise.Endpoint); err != nil {
		return err
	}
	token, err := m.decrypt(settings.Hookwise.TokenCipher)
	if err != nil {
		return err
	}
	payload := []byte(`{"event_id":"openvasconf-connection-test","state":"connection_test","summary":"openvasconf connection test"}`)
	_, err = m.send(ctx, settings.Hookwise.Endpoint, token, payload)
	return err
}

// Retry makes every pending failed event immediately eligible again.
func (m *Manager) Retry(ctx context.Context) error {
	if err := m.repository.RetryHookwiseEvents(ctx); err != nil {
		return err
	}
	m.Trigger()
	return nil
}

// Stats returns durable delivery counts for the settings page.
func (m *Manager) Stats(ctx context.Context) (store.HookwiseStats, error) {
	return m.repository.HookwiseStats(ctx)
}

// Health implements the web health-strip component without exposing secrets.
func (m *Manager) Health(ctx context.Context) (state, detail, guidance, link string) {
	settings, err := m.repository.Settings(ctx)
	if err != nil {
		return "degraded", "ticket settings unavailable", "Check the service logs for repository errors.", "/settings"
	}
	if !settings.Hookwise.Enabled {
		return "ok", "ticket integration disabled", "", "/settings"
	}
	if len(m.key) != 32 || settings.Hookwise.Endpoint == "" || settings.Hookwise.TokenCipher == "" {
		return "degraded", "ticket integration incomplete", "Configure the endpoint, token, and deployment encryption key.", "/settings"
	}
	stats, err := m.repository.HookwiseStats(ctx)
	if err != nil {
		return "degraded", "ticket delivery status unavailable", "Check the service logs.", "/settings"
	}
	if stats.Failed > 0 {
		return "degraded", fmt.Sprintf("%d ticket event(s) retrying", stats.Failed), "Inspect Hookwise connectivity and retry failed events.", "/settings"
	}
	if stats.Pending > 0 {
		return "ok", fmt.Sprintf("%d ticket event(s) queued", stats.Pending), "", "/findings"
	}
	return "ok", "ticket delivery current", "", "/findings"
}

func (m *Manager) send(ctx context.Context, endpoint, token string, payload []byte) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := m.client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("sending webhook: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, responseLimit))
	closeErr := response.Body.Close()
	if readErr != nil {
		return response.StatusCode, fmt.Errorf("reading webhook response: %w", errors.Join(readErr, closeErr))
	}
	if closeErr != nil {
		return response.StatusCode, fmt.Errorf("closing webhook response: %w", closeErr)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("webhook returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return response.StatusCode, nil
}

func validateEndpoint(value string) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(value))
	if err != nil {
		return errors.New("hookwise endpoint must be a valid absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("hookwise endpoint must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil {
		return errors.New("hookwise endpoint must contain a host and no embedded credentials")
	}
	return nil
}

func (m *Manager) encrypt(value string) (string, error) {
	if len(m.key) != 32 {
		return "", errors.New("hookwise encryption key is not configured in the deployment")
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", fmt.Errorf("creating encryption cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating authenticated encryption: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating encryption nonce: %w", err)
	}
	ciphertext := aead.Seal(nonce, nonce, []byte(value), nil)
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func (m *Manager) decrypt(value string) (string, error) {
	if value == "" {
		return "", errors.New("hookwise bearer token is not configured")
	}
	if len(m.key) != 32 {
		return "", errors.New("hookwise encryption key is not configured in the deployment")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return "", errors.New("hookwise bearer token is corrupt")
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", fmt.Errorf("creating decryption cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating authenticated decryption: %w", err)
	}
	if len(ciphertext) < aead.NonceSize() {
		return "", errors.New("hookwise bearer token is corrupt")
	}
	plaintext, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], nil)
	if err != nil {
		return "", errors.New("hookwise bearer token cannot be decrypted")
	}
	return string(plaintext), nil
}

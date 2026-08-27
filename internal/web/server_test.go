package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openvasconf/internal/auth"
	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
	"openvasconf/internal/updater"
)

const testAdminPassword = "correct horse battery staple"

type fakeGreenbone struct {
	options gmp.Options
}

func (f fakeGreenbone) Ping(context.Context) (string, error) {
	return "22.4-test", nil
}

func (f fakeGreenbone) Options(context.Context) (gmp.Options, error) {
	return f.options, nil
}

type triggerCounter struct {
	count atomic.Int32
}

func (c *triggerCounter) Trigger() {
	c.count.Add(1)
}

type testWebApp struct {
	server     *httptest.Server
	client     *http.Client
	repository *store.Store
	syncer     *triggerCounter
}

func newTestWebApp(t *testing.T) testWebApp {
	return newTestWebAppWithUpdater(t, nil)
}

func newTestWebAppWithUpdater(t *testing.T, updateManager updater.Manager) testWebApp {
	t.Helper()
	repository, err := store.Open(
		context.Background(),
		filepath.Join(t.TempDir(), "openvasconf.db"),
		"Europe/Vienna",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })

	authenticator := auth.New(repository, time.Hour)
	if err := authenticator.Bootstrap(context.Background(), testAdminPassword); err != nil {
		t.Fatal(err)
	}
	options := gmp.Options{
		Scanners:    []gmp.Option{{ID: "scanner-1", Name: "OpenVAS Default"}},
		ScanConfigs: []gmp.Option{{ID: "config-1", Name: "Full and fast"}},
		PortLists:   []gmp.Option{{ID: "ports-1", Name: "All IANA assigned TCP"}},
	}
	syncer := &triggerCounter{}
	application, err := New(Options{
		Repository: repository,
		Auth:       authenticator,
		Greenbone:  fakeGreenbone{options: options},
		Syncer:     syncer,
		Updater:    updateManager,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return testWebApp{
		server:     server,
		client:     &http.Client{Jar: jar},
		repository: repository,
		syncer:     syncer,
	}
}

type fakeUpdateManager struct {
	status       updater.Status
	configured   updater.Policy
	triggered    updater.Kind
	acknowledged bool
}

func (m *fakeUpdateManager) Status(context.Context) (updater.Status, error) {
	return m.status, nil
}

func (m *fakeUpdateManager) Configure(_ context.Context, policy updater.Policy) error {
	m.configured = policy
	return nil
}

func (m *fakeUpdateManager) Trigger(
	_ context.Context,
	kind updater.Kind,
	_ updater.TriggerRequest,
) (updater.Operation, error) {
	m.triggered = kind
	return updater.Operation{ID: "test-operation", Kind: kind}, nil
}

func (m *fakeUpdateManager) Acknowledge(context.Context) error {
	m.acknowledged = true
	return nil
}

func TestLoginCSRFAndSecurityHeaders(t *testing.T) {
	app := newTestWebApp(t)

	response, err := app.client.Get(app.server.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", response.StatusCode)
	}
	if response.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("content security policy header is missing")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("closing login response body: %v", err)
	}

	form := url.Values{"username": {"admin"}, "password": {testAdminPassword}}
	request, err := http.NewRequest(http.MethodPost, app.server.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = app.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("post without csrf status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("closing forbidden response body: %v", err)
	}

	login(t, app)
	response, err = app.client.Get(app.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", response.StatusCode)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("closing dashboard response body: %v", err)
	}
}

func TestCookieSecurityPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		secureCookies  bool
		trustProxyTLS  bool
		tls            bool
		forwardedProto string
		wantSecure     bool
	}{
		{name: "plain HTTP"},
		{name: "forced secure", secureCookies: true, wantSecure: true},
		{name: "direct TLS", tls: true, wantSecure: true},
		{
			name:           "trusted TLS proxy",
			trustProxyTLS:  true,
			forwardedProto: "https",
			wantSecure:     true,
		},
		{name: "untrusted TLS proxy", forwardedProto: "https"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := &Server{
				secureCookies:       test.secureCookies,
				trustProxyTLSHeader: test.trustProxyTLS,
			}
			request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			if test.tls {
				request.TLS = &tls.ConnectionState{}
			}
			request.Header.Set("X-Forwarded-Proto", test.forwardedProto)
			if got := server.isSecure(request); got != test.wantSecure {
				t.Errorf("isSecure() = %t, want %t", got, test.wantSecure)
			}
		})
	}
}

func TestCustomerPreviewCreateAndSoftDelete(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)

	preview := url.Values{
		"name":     {"testcomp1"},
		"networks": {"10.1.0.0/16 # LAN\n192.168.10.0 # printer\n7.7.7.7/32 # internet"},
	}
	response := postForm(t, app, "/customers/preview", preview)
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("preview status = %d: %s", response.StatusCode, body)
	}
	for _, expected := range []string{"3840 IPs", "19 target/task pairs", "testcomp1_WAN_Target1"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("preview does not contain %q", expected)
		}
	}
	match := regexp.MustCompile(`name="preview_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("signed preview token not rendered: %s", body)
	}

	response = postForm(t, app, "/customers", url.Values{"preview_token": {match[1]}})
	_ = readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create final status = %d", response.StatusCode)
	}
	customers, err := app.repository.Customers(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(customers) != 1 {
		t.Fatalf("customer count = %d, want 1", len(customers))
	}
	created := customers[0]
	if len(created.Networks) != 3 {
		t.Fatalf("network count = %d, want 3", len(created.Networks))
	}
	wantInputs := map[string]string{
		"10.1.0.0/16":     "10.1.0.0/16 # LAN",
		"192.168.10.0/32": "192.168.10.0 # printer",
		"7.7.7.7/32":      "7.7.7.7/32 # internet",
	}
	for _, network := range created.Networks {
		if want := wantInputs[network.Prefix]; network.Input != want {
			t.Errorf("network %s input = %q, want %q", network.Prefix, network.Input, want)
		}
	}
	if created.ScheduleWeekday < 1 || created.ScheduleWeekday > 4 {
		t.Fatalf("weekday = %d, want Monday through Thursday", created.ScheduleWeekday)
	}
	if created.ScheduleMinute < 7*60 || created.ScheduleMinute > 15*60 {
		t.Fatalf("schedule minute = %d, want 07:00 through 15:00", created.ScheduleMinute)
	}
	if app.syncer.count.Load() != 1 {
		t.Fatalf("sync trigger count = %d, want 1", app.syncer.count.Load())
	}

	response = postForm(t, app, "/customers/"+created.ID+"/delete", nil)
	_ = readBody(t, response)
	allCustomers, err := app.repository.Customers(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(allCustomers) != 1 || allCustomers[0].DeletedAt == nil {
		t.Fatal("customer was not retained as a soft-deleted record")
	}
	if app.syncer.count.Load() != 2 {
		t.Fatalf("sync trigger count = %d, want 2", app.syncer.count.Load())
	}
}

func TestJSONPreviewAndSettingsOverride(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)

	payload, err := json.Marshal(map[string]any{
		"customer_name": "edge",
		"networks":      []string{"192.168.10.10", "8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, app.server.URL+"/api/preview", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrfCookie(t, app))
	response, err := app.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "PrivateIP") {
		t.Fatalf("api preview = %d: %s", response.StatusCode, body)
	}

	settingsForm := url.Values{
		"scanner_id":     {"scanner-1"},
		"scan_config_id": {"config-1"},
		"port_list_id":   {"ports-1"},
		"timezone":       {"Europe/Vienna"},
	}
	response = postForm(t, app, "/settings", settingsForm)
	_ = readBody(t, response)
	settings, err := app.repository.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if settings.Scanner.ID != "scanner-1" || settings.ScanConfig.ID != "config-1" || settings.PortList.ID != "ports-1" {
		t.Fatalf("settings were not persisted: %#v", settings)
	}
}

func TestUpdaterPagePolicyAndStackTrigger(t *testing.T) {
	phaseStartedAt := time.Date(2026, 8, 27, 10, 15, 0, 0, time.UTC)
	manager := &fakeUpdateManager{status: updater.Status{
		ProtocolVersion: updater.ProtocolVersion,
		Available:       true,
		Policy:          updater.DefaultPolicy("Europe/Vienna"),
		Active: &updater.Operation{
			ID: "operation-active", Kind: updater.KindFeed,
			State: updater.StateRunning, Phase: "importing",
			Detail:    "Waiting for Greenbone feed import.",
			StartedAt: phaseStartedAt.Add(-time.Minute), PhaseStartedAt: phaseStartedAt,
		},
	}}
	app := newTestWebAppWithUpdater(t, manager)
	login(t, app)

	response, err := app.client.Get(app.server.URL + "/updates")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "Greenbone updates") {
		t.Fatalf("updates page = %d: %s", response.StatusCode, body)
	}
	if !strings.Contains(body, "data-update-phase-start=") ||
		!strings.Contains(body, "LATEST PROGRESS") ||
		!strings.Contains(body, "data-update-elapsed") {
		t.Fatalf("updates page lacks phase progress markup: %s", body)
	}

	policyForm := url.Values{
		"feed_enabled":                 {"on"},
		"feed_time":                    {"01:30"},
		"stack_enabled":                {"on"},
		"stack_weekday":                {"7"},
		"stack_time":                   {"03:00"},
		"stack_window_minutes":         {"180"},
		"update_timezone":              {"Europe/Vienna"},
		"backup_retention":             {"4"},
		"verification_timeout_minutes": {"120"},
	}
	response = postForm(t, app, "/updates/settings", policyForm)
	_ = readBody(t, response)
	if manager.configured.FeedMinute != 90 || !manager.configured.StackEnabled {
		t.Fatalf("configured policy = %#v", manager.configured)
	}
	stored, err := app.repository.UpdatePolicy(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if stored != manager.configured {
		t.Fatalf("stored policy = %#v, configured = %#v", stored, manager.configured)
	}

	response = postForm(t, app, "/updates/stack", nil)
	_ = readBody(t, response)
	if manager.triggered != updater.KindStack {
		t.Fatalf("triggered kind = %q, want %q", manager.triggered, updater.KindStack)
	}
	events, err := app.repository.AuditEvents(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[0].ResourceKind != "updater" {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestUpdaterJavaScriptUsesAdaptivePolling(t *testing.T) {
	t.Parallel()
	contents, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(contents)
	for _, expected := range []string{
		"const activeDelay = 2000",
		"const warmIdleDelay = 10000",
		"const coldIdleDelay = 30000",
		"visibilitychange",
		"data-update-phase-start",
	} {
		if !strings.Contains(script, expected) {
			t.Errorf("app.js does not contain %q", expected)
		}
	}
}

func TestSignedPreviewConfirmationAndTamperRejection(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)
	form := url.Values{
		"name": {"signed-customer"}, "description": {"reviewed definition"},
		"tags": {"PROD, vienna"}, "networks": {"10.20.0.1,8.8.8.8"},
		"schedule_weekday": {"2"}, "schedule_time": {"09:30"},
	}
	response := postForm(t, app, "/customers/preview", form)
	body := readBody(t, response)
	match := regexp.MustCompile(`name="preview_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("signed preview token not rendered: %s", body)
	}

	parts := strings.Split(match[1], ".")
	if len(parts) != 2 || parts[1] == "" {
		t.Fatalf("invalid signed preview token: %q", match[1])
	}
	changedSignature := []byte(parts[1])
	if changedSignature[0] == 'A' {
		changedSignature[0] = 'B'
	} else {
		changedSignature[0] = 'A'
	}
	tamperedTokens := []struct {
		name  string
		token string
	}{
		{name: "non-canonical encoding", token: match[1][:len(match[1])-1] + "x"},
		{name: "changed signature", token: parts[0] + "." + string(changedSignature)},
	}
	for _, test := range tamperedTokens {
		t.Run(test.name, func(t *testing.T) {
			tamperedResponse := postForm(t, app, "/customers", url.Values{"preview_token": {test.token}})
			if body := readBody(t, tamperedResponse); !strings.Contains(body, "preview confirmation is invalid") {
				t.Fatalf("tampered confirmation was not rejected: %s", body)
			}
		})
	}

	response = postForm(t, app, "/customers", url.Values{"preview_token": {match[1]}})
	_ = readBody(t, response)
	values, err := app.repository.Customers(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].Description != "reviewed definition" || values[0].ScheduleMinute != 9*60+30 {
		t.Fatalf("confirmed customer = %#v", values)
	}
}

func login(t *testing.T, app testWebApp) {
	t.Helper()
	response, err := app.client.Get(app.server.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	form := url.Values{
		"username":   {"admin"},
		"password":   {testAdminPassword},
		"csrf_token": {csrfCookie(t, app)},
	}
	response = postForm(t, app, "/login", form)
	_ = readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login final status = %d", response.StatusCode)
	}
}

func postForm(t *testing.T, app testWebApp, path string, form url.Values) *http.Response {
	t.Helper()
	if form == nil {
		form = make(url.Values)
	}
	form.Set("csrf_token", csrfCookie(t, app))
	response, err := app.client.PostForm(app.server.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func csrfCookie(t *testing.T, app testWebApp) string {
	t.Helper()
	parsed, err := url.Parse(app.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range app.client.Jar.Cookies(parsed) {
		if cookie.Name == csrfCookieName {
			return cookie.Value
		}
	}
	t.Fatal("csrf cookie is missing")
	return ""
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("closing response body: %v", err)
	}
	return string(body)
}

package web

import (
	"bytes"
	"context"
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

func TestCustomerPreviewCreateAndSoftDelete(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)

	preview := url.Values{
		"name":     {"testcomp1"},
		"networks": {"10.1.0.0/16\n192.168.10.0\n7.7.7.7/32"},
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

	tampered := match[1][:len(match[1])-1] + "x"
	response = postForm(t, app, "/customers", url.Values{"preview_token": {tampered}})
	if body := readBody(t, response); !strings.Contains(body, "preview confirmation is invalid") {
		t.Fatalf("tampered confirmation was not rejected: %s", body)
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

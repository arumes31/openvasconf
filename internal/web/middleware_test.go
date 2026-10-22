package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginLimiterBudgets(t *testing.T) {
	t.Parallel()

	now := time.Now()
	limiter := newLoginLimiter()
	for range loginClientFailures {
		if !limiter.allowed("192.0.2.1", now) {
			t.Fatal("client blocked before its failure budget was spent")
		}
		limiter.failure("192.0.2.1", now)
	}
	if limiter.allowed("192.0.2.1", now) {
		t.Error("client allowed after spending its failure budget")
	}
	if !limiter.allowed("192.0.2.2", now) {
		t.Error("unrelated client blocked by another client's failures")
	}
	if !limiter.allowed("192.0.2.1", now.Add(loginWindow+time.Second)) {
		t.Error("client still blocked after the window elapsed")
	}

	global := newLoginLimiter()
	for index := range loginGlobalFailures {
		global.failure(fmt.Sprintf("198.51.100.%d", index), now)
	}
	if global.allowed("203.0.113.9", now) {
		t.Error("fresh client allowed after the global failure budget was spent")
	}
}

func TestLoginLimiterBoundsClientMap(t *testing.T) {
	t.Parallel()

	now := time.Now()
	limiter := newLoginLimiter()
	for index := range loginMaxClients + 100 {
		limiter.failure(fmt.Sprintf("client-%d", index), now)
	}
	if got := len(limiter.attempts); got > loginMaxClients+1 {
		t.Errorf("tracked clients = %d, want at most %d", got, loginMaxClients+1)
	}
	limiter.global = nil
	limiter.allowed("client-0", now.Add(loginWindow+time.Second))
	if got := len(limiter.attempts); got != 0 {
		t.Errorf("tracked clients after sweep = %d, want 0", got)
	}
}

func TestLoginClientKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		trustProxy bool
		remoteAddr string
		forwarded  []string
		want       string
	}{
		{name: "ipv4 peer", remoteAddr: "192.0.2.10:5000", want: "192.0.2.10"},
		{name: "ipv6 peer keyed by /64", remoteAddr: "[2001:db8:1:2:3:4:5:6]:5000", want: "2001:db8:1:2::/64"},
		{name: "mapped ipv4", remoteAddr: "[::ffff:192.0.2.10]:5000", want: "192.0.2.10"},
		{name: "untrusted forwarded header ignored", remoteAddr: "10.0.0.2:5000", forwarded: []string{"203.0.113.5"}, want: "10.0.0.2"},
		{
			name: "trusted proxy uses rightmost entry", trustProxy: true, remoteAddr: "10.0.0.2:5000",
			forwarded: []string{"198.51.100.1, 203.0.113.5"}, want: "203.0.113.5",
		},
		{
			name: "trusted proxy uses last header", trustProxy: true, remoteAddr: "10.0.0.2:5000",
			forwarded: []string{"198.51.100.1", "203.0.113.6"}, want: "203.0.113.6",
		},
		{name: "trusted proxy without header", trustProxy: true, remoteAddr: "10.0.0.2:5000", want: "10.0.0.2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := &Server{trustProxyClientIP: test.trustProxy}
			request := httptest.NewRequest(http.MethodPost, "http://example.test/login", nil)
			request.RemoteAddr = test.remoteAddr
			for _, value := range test.forwarded {
				request.Header.Add("X-Forwarded-For", value)
			}
			if got := server.loginClient(request); got != test.want {
				t.Errorf("loginClient() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHealthReadyDoesNotDiscloseComponents(t *testing.T) {
	app := newTestWebApp(t)

	response, err := app.client.Get(app.server.URL + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("ready status = %d: %s", response.StatusCode, body)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decoding ready response: %v", err)
	}
	if len(payload) != 1 || payload["status"] != "ready" {
		t.Errorf("ready response = %s, want only a status", body)
	}
	if strings.Contains(body, "22.4-test") {
		t.Errorf("ready response discloses the Greenbone version: %s", body)
	}
}

func TestLoginAndLogoutRotateCSRFToken(t *testing.T) {
	app := newTestWebApp(t)

	response, err := app.client.Get(app.server.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	before := csrfCookie(t, app)
	login(t, app)
	afterLogin := csrfCookie(t, app)
	if afterLogin == before {
		t.Error("csrf token survived login")
	}
	response = postForm(t, app, "/logout", nil)
	_ = readBody(t, response)
	if csrfCookie(t, app) == afterLogin {
		t.Error("csrf token survived logout")
	}
}

func TestLogoutAllRevokesOtherSessions(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)

	otherJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	other := app
	other.client = &http.Client{Jar: otherJar}
	login(t, other)

	response := postForm(t, app, "/logout/all", nil)
	_ = readBody(t, response)

	noRedirect := &http.Client{
		Jar: otherJar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err = noRedirect.Get(app.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/login" {
		t.Errorf("other session after logout-all: status %d location %q", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestHSTSOnlyOverHTTPS(t *testing.T) {
	t.Parallel()

	server := &Server{trustProxyTLSHeader: true}
	handler := server.securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	plain := httptest.NewRecorder()
	handler.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if got := plain.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("plain HTTP HSTS = %q, want none", got)
	}

	proxied := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	handler.ServeHTTP(proxied, request)
	if got := proxied.Header().Get("Strict-Transport-Security"); got == "" {
		t.Error("trusted HTTPS proxy response lacks HSTS")
	}
}

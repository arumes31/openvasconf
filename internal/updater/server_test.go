package updater

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type managerStub struct {
	status       Status
	statusErr    error
	configureErr error
	triggerErr   error
	ackErr       error
	configured   Policy
	triggerKind  Kind
	trigger      TriggerRequest
}

func (m *managerStub) Status(context.Context) (Status, error) {
	return m.status, m.statusErr
}

func (m *managerStub) Configure(_ context.Context, policy Policy) error {
	m.configured = policy
	return m.configureErr
}

func (m *managerStub) Trigger(
	_ context.Context,
	kind Kind,
	request TriggerRequest,
) (Operation, error) {
	m.triggerKind = kind
	m.trigger = request
	return Operation{ID: "operation-1", Kind: kind}, m.triggerErr
}

func (m *managerStub) Acknowledge(context.Context) error {
	return m.ackErr
}

func TestNewHandlerRequiresManager(t *testing.T) {
	t.Parallel()

	if _, err := NewHandler(nil); err == nil {
		t.Fatal("NewHandler(nil) error = nil")
	}
}

func TestHandlerRoutesSuccessfulRequests(t *testing.T) {
	t.Parallel()

	policy := DefaultPolicy("UTC")
	manager := &managerStub{status: Status{ProtocolVersion: ProtocolVersion, Available: true}}
	handler, err := NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantKind   Kind
	}{
		{name: "status", method: http.MethodGet, path: "/v1/status", wantStatus: http.StatusOK},
		{name: "configure", method: http.MethodPut, path: "/v1/policy", body: jsonValue(t, policy), wantStatus: http.StatusNoContent},
		{name: "check", method: http.MethodPost, path: "/v1/operations/check", body: `{"idempotency_key":"key-1","trigger":"admin"}`, wantStatus: http.StatusAccepted, wantKind: KindCheck},
		{name: "feed", method: http.MethodPost, path: "/v1/operations/feed", body: `{"idempotency_key":"key-2","trigger":"admin"}`, wantStatus: http.StatusAccepted, wantKind: KindFeed},
		{name: "stack", method: http.MethodPost, path: "/v1/operations/stack", body: `{"idempotency_key":"key-3","trigger":"admin"}`, wantStatus: http.StatusAccepted, wantKind: KindStack},
		{name: "acknowledge", method: http.MethodPost, path: "/v1/acknowledge", body: `{}`, wantStatus: http.StatusNoContent},
		{name: "not found", method: http.MethodGet, path: "/missing", wantStatus: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body)
			}
			if response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("X-Frame-Options") != "DENY" {
				t.Errorf("security headers = %#v", response.Header())
			}
			if test.wantKind != "" && manager.triggerKind != test.wantKind {
				t.Errorf("trigger kind = %q, want %q", manager.triggerKind, test.wantKind)
			}
		})
	}
	if manager.configured.Timezone != policy.Timezone {
		t.Errorf("configured policy = %#v", manager.configured)
	}
}

func TestHandlerReturnsManagerAndDecodeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		manager    *managerStub
		wantStatus int
		wantBody   string
	}{
		{name: "status unavailable", method: http.MethodGet, path: "/v1/status", manager: &managerStub{statusErr: errors.New("offline")}, wantStatus: http.StatusServiceUnavailable, wantBody: "status unavailable"},
		{name: "invalid JSON", method: http.MethodPut, path: "/v1/policy", body: `{`, manager: &managerStub{}, wantStatus: http.StatusBadRequest, wantBody: "invalid request body"},
		{name: "unknown field", method: http.MethodPut, path: "/v1/policy", body: `{"unknown":true}`, manager: &managerStub{}, wantStatus: http.StatusBadRequest, wantBody: "invalid request body"},
		{name: "two JSON values", method: http.MethodPost, path: "/v1/acknowledge", body: `{} {}`, manager: &managerStub{}, wantStatus: http.StatusBadRequest, wantBody: "one JSON value"},
		{name: "configure rejected", method: http.MethodPut, path: "/v1/policy", body: jsonValue(t, DefaultPolicy("UTC")), manager: &managerStub{configureErr: errors.New("bad policy")}, wantStatus: http.StatusBadRequest, wantBody: "bad policy"},
		{name: "trigger busy", method: http.MethodPost, path: "/v1/operations/check", body: `{"idempotency_key":"key","trigger":"admin"}`, manager: &managerStub{triggerErr: ErrBusy}, wantStatus: http.StatusConflict, wantBody: "another update"},
		{name: "trigger paused", method: http.MethodPost, path: "/v1/operations/stack", body: `{"idempotency_key":"key","trigger":"admin"}`, manager: &managerStub{triggerErr: ErrPaused}, wantStatus: http.StatusLocked, wantBody: "paused"},
		{name: "trigger rejected", method: http.MethodPost, path: "/v1/operations/feed", body: `{"idempotency_key":"key","trigger":"admin"}`, manager: &managerStub{triggerErr: errors.New("rejected")}, wantStatus: http.StatusBadRequest, wantBody: "rejected"},
		{name: "acknowledge unavailable", method: http.MethodPost, path: "/v1/acknowledge", body: `{}`, manager: &managerStub{ackErr: errors.New("offline")}, wantStatus: http.StatusServiceUnavailable, wantBody: "acknowledgement failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(test.manager)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), test.wantBody) {
				t.Fatalf("response = %d %q, want %d containing %q", response.Code, response.Body.String(), test.wantStatus, test.wantBody)
			}
		})
	}
}

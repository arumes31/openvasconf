package updater

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonValue(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func clientForHandler(handler http.Handler) *Client {
	return &Client{httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := &responseRecorder{header: make(http.Header)}
		handler.ServeHTTP(response, request)
		return response.response(request), nil
	})}}
}

type responseRecorder struct {
	header http.Header
	body   strings.Builder
	status int
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) Write(contents []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(contents)
}

func (r *responseRecorder) WriteHeader(status int) { r.status = status }

func (r *responseRecorder) response(request *http.Request) *http.Response {
	return &http.Response{
		StatusCode: r.status,
		Header:     r.header,
		Body:       io.NopCloser(strings.NewReader(r.body.String())),
		Request:    request,
	}
}

func TestClientRoundTripsProtocol(t *testing.T) {
	t.Parallel()

	manager := &managerStub{status: Status{ProtocolVersion: ProtocolVersion, Available: true}}
	handler, err := NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	client := clientForHandler(handler)
	status, err := client.Status(t.Context())
	if err != nil || !status.Available {
		t.Fatalf("Status() = %#v, %v", status, err)
	}
	policy := DefaultPolicy("UTC")
	if err := client.Configure(t.Context(), policy); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	for _, kind := range []Kind{KindCheck, KindFeed, KindStack} {
		operation, triggerErr := client.Trigger(t.Context(), kind, TriggerRequest{
			IdempotencyKey: "key-" + string(kind), Trigger: TriggerAdmin,
		})
		if triggerErr != nil || operation.Kind != kind {
			t.Fatalf("Trigger(%q) = %#v, %v", kind, operation, triggerErr)
		}
	}
	if err := client.Acknowledge(t.Context()); err != nil {
		t.Fatalf("Acknowledge() error = %v", err)
	}
}

func TestClientValidatesInputsAndMapsErrors(t *testing.T) {
	t.Parallel()

	invalid := DefaultPolicy("UTC")
	invalid.Timezone = ""
	client := &Client{httpClient: &http.Client{}}
	if err := client.Configure(t.Context(), invalid); err == nil {
		t.Fatal("Configure(invalid) error = nil")
	}
	if _, err := client.Trigger(t.Context(), "unknown", TriggerRequest{}); err == nil {
		t.Fatal("Trigger(unknown) error = nil")
	}

	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
		want    string
	}{
		{name: "busy", status: http.StatusConflict, body: `{"error":"busy now"}`, wantErr: ErrBusy},
		{name: "paused", status: http.StatusLocked, body: `{"error":"paused now"}`, wantErr: ErrPaused},
		{name: "plain error", status: http.StatusBadGateway, body: `not-json`, want: "Bad Gateway"},
		{name: "invalid success JSON", status: http.StatusOK, body: `{`, want: "decoding updater response"},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", maxResponseBytes+1), want: "size limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header), Request: request}, nil
			})}}
			_, err := client.Status(t.Context())
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want errors.Is(%v)", err, test.wantErr)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestClientReportsUnavailableTransport(t *testing.T) {
	t.Parallel()

	client := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}}
	if _, err := client.Status(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Status() error = %v, want ErrUnavailable", err)
	}

	unixClient := NewClient("missing.sock", time.Millisecond)
	if unixClient.httpClient.Timeout != time.Millisecond {
		t.Errorf("NewClient timeout = %s", unixClient.httpClient.Timeout)
	}
}

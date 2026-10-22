package hookwise

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/store"
)

func TestManagerDispatchesOpenAndCloseLifecycle(t *testing.T) {
	ctx := t.Context()
	repository, err := store.Open(ctx, filepath.Join(t.TempDir(), "hookwise.db"), "Europe/Vienna")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = repository.Close() })

	value := customer.Customer{
		ID: "customer-1", Name: "Customer One", SafeName: "customer-one",
		ConnectWiseCustomerName: "Acme Europe GmbH",
		ScheduleWeekday:         1, ScheduleMinute: 480, Timezone: "Europe/Vienna",
	}
	if err := repository.CreateCustomer(ctx, value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	snapshot := store.ReportSnapshot{
		ReportID: "report-1", TaskID: "task-1", TaskName: "Customer One WAN",
		CustomerID: value.ID, ScanStart: now.Add(-time.Hour), ScanEnd: now, Status: "Done",
	}
	finding := store.FindingSnapshot{
		Fingerprint: "v1:high-finding", NVTOID: "1.3.6.1.4.1", Title: "Remote code execution",
		Host: "10.0.0.10", Port: "443/tcp", Severity: 9.8, Threat: "High",
		CVEs: []string{"CVE-2026-0001"}, Remediation: "Install the vendor update.",
	}
	if err := repository.SaveReportSnapshot(ctx, snapshot, []store.FindingSnapshot{finding}); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}

	var mu sync.Mutex
	events := make([]map[string]any, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer ticket-secret" {
			t.Errorf("Authorization = %q", got)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("ReadAll() error = %v", readErr)
		}
		var event map[string]any
		if err := json.Unmarshal(body, &event); err != nil {
			t.Errorf("json.Unmarshal() error = %v", err)
		}
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
		response.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	manager := New(repository, []byte("0123456789abcdef0123456789abcdef"), time.Second, slog.Default()).
		AllowInsecureHTTP(true)
	allowLoopbackDial(manager)
	if err := manager.Save(ctx, true, server.URL+"/webhook/test", "ticket-secret"); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	settings, err := repository.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings() error = %v", err)
	}
	if settings.Hookwise.TokenCipher == "" || settings.Hookwise.TokenCipher == "ticket-secret" {
		t.Fatalf("token cipher was not encrypted: %q", settings.Hookwise.TokenCipher)
	}
	if err := manager.DispatchOnce(ctx); err != nil {
		t.Fatalf("first DispatchOnce() error = %v", err)
	}

	rows, _, err := repository.CurrentFindings(ctx, store.FindingQuery{})
	if err != nil || len(rows) != 1 || rows[0].TicketState != "open" {
		t.Fatalf("current ticket state = %#v, error = %v", rows, err)
	}
	if err := manager.RecreateFinding(ctx, value.ID, "task-1", finding.Fingerprint); err != nil {
		t.Fatalf("RecreateFinding() error = %v", err)
	}
	if err := manager.DispatchOnce(ctx); err != nil {
		t.Fatalf("recreate DispatchOnce() error = %v", err)
	}
	if err := repository.UpsertAnnotation(ctx, store.FindingAnnotation{
		CustomerID: value.ID, TaskID: "task-1", Fingerprint: finding.Fingerprint,
		Disposition: store.DispositionActive, Justification: "patched",
		Operator: "admin", RemediationState: store.RemediationResolved,
	}); err != nil {
		t.Fatalf("UpsertAnnotation() error = %v", err)
	}
	if err := manager.DispatchOnce(ctx); err != nil {
		t.Fatalf("second DispatchOnce() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	if events[0]["state"] != "open" ||
		events[0]["connectwise_customer_name"] != "Acme Europe GmbH" {
		t.Errorf("open event = %#v", events[0])
	}
	if events[1]["state"] != "open" || events[1]["event_id"] == events[0]["event_id"] {
		t.Errorf("recreated event = %#v", events[1])
	}
	if events[2]["state"] != "closed" || events[2]["finding_key"] != events[0]["finding_key"] {
		t.Errorf("close event = %#v", events[2])
	}
	if events[1]["summary"] != events[0]["summary"] || events[2]["summary"] != events[0]["summary"] {
		t.Errorf(
			"ticket summary changed across lifecycle: %q → %q → %q",
			events[0]["summary"],
			events[1]["summary"],
			events[2]["summary"],
		)
	}
}

// allowLoopbackDial replaces the internal-address guard so tests can deliver
// to httptest servers on 127.0.0.1.
func allowLoopbackDial(manager *Manager) {
	manager.client.Transport.(*http.Transport).DialContext = (&net.Dialer{}).DialContext
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		allowHTTP bool
		wantErr   bool
	}{
		{name: "https", value: "https://hookwise.example/webhook/1"},
		{name: "internal http rejected by default", value: "http://10.0.0.5:8080/webhook/1", wantErr: true},
		{name: "internal http with opt-in", value: "http://10.0.0.5:8080/webhook/1", allowHTTP: true},
		{name: "embedded credentials", value: "https://user:pass@example.com/hook", wantErr: true},
		{name: "unsupported scheme", value: "file:///tmp/hook", allowHTTP: true, wantErr: true},
		{name: "relative", value: "/webhook/1", wantErr: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateEndpoint(testCase.value, testCase.allowHTTP)
			if (err != nil) != testCase.wantErr {
				t.Errorf("validateEndpoint(%q) error = %v, wantErr %t", testCase.value, err, testCase.wantErr)
			}
		})
	}
}

func TestSaveRequiresTokenWhenEndpointHostChanges(t *testing.T) {
	ctx := t.Context()
	repository, err := store.Open(ctx, filepath.Join(t.TempDir(), "hookwise.db"), "Europe/Vienna")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	manager := New(repository, []byte("0123456789abcdef0123456789abcdef"), time.Second, slog.Default())

	if err := manager.Save(ctx, true, "https://hookwise.example/w/1", "ticket-secret"); err != nil {
		t.Fatalf("Save(initial) error = %v", err)
	}
	if err := manager.Save(ctx, true, "https://hookwise.example/w/2", ""); err != nil {
		t.Fatalf("Save(same host) error = %v", err)
	}
	if err := manager.Save(ctx, true, "https://attacker.example/w/2", ""); err == nil {
		t.Fatal("Save(changed host without token) error = nil, want error")
	}
	settings, err := repository.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings() error = %v", err)
	}
	if settings.Hookwise.Endpoint != "https://hookwise.example/w/2" {
		t.Errorf("endpoint = %q, want unchanged", settings.Hookwise.Endpoint)
	}
	if err := manager.Save(ctx, false, "https://other.example/w/3", ""); err != nil {
		t.Fatalf("Save(disabled, changed host) error = %v", err)
	}
	settings, err = repository.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings() error = %v", err)
	}
	if settings.Hookwise.TokenCipher != "" {
		t.Error("stored token was kept for a changed endpoint host")
	}
	if err := manager.Save(ctx, true, "https://other.example/w/3", "new-secret"); err != nil {
		t.Fatalf("Save(changed host with token) error = %v", err)
	}
}

func TestRefuseInternalAddress(t *testing.T) {
	tests := []struct {
		address string
		wantErr bool
	}{
		{address: "10.0.0.5:443"},
		{address: "192.168.1.10:8080"},
		{address: "203.0.113.7:443"},
		{address: "127.0.0.1:8080", wantErr: true},
		{address: "[::1]:443", wantErr: true},
		{address: "169.254.169.254:80", wantErr: true},
		{address: "[fe80::1]:443", wantErr: true},
		{address: "0.0.0.0:443", wantErr: true},
		{address: "[::ffff:127.0.0.1]:443", wantErr: true},
		{address: "224.0.0.1:443", wantErr: true},
	}
	for _, testCase := range tests {
		if err := refuseInternalAddress("tcp", testCase.address, nil); (err != nil) != testCase.wantErr {
			t.Errorf("refuseInternalAddress(%q) error = %v, wantErr %t", testCase.address, err, testCase.wantErr)
		}
	}
}

func TestSendDoesNotPersistResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(response, "remote controlled content")
	}))
	t.Cleanup(server.Close)
	manager := New(nil, nil, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	allowLoopbackDial(manager)
	status, err := manager.send(context.Background(), server.URL, "token", []byte("{}"))
	if status != http.StatusBadRequest || err == nil {
		t.Fatalf("send() = %d, %v", status, err)
	}
	if strings.Contains(err.Error(), "remote controlled content") {
		t.Errorf("send() error contains response body: %v", err)
	}
}

func TestDefaultTransportRefusesLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	manager := New(nil, nil, time.Second, slog.Default())
	if _, err := manager.send(context.Background(), server.URL, "token", []byte("{}")); err == nil {
		t.Fatal("send() to loopback error = nil, want refusal")
	}
}

package hookwise

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
		ID: "customer-1", Name: "Customer One", SafeName: "customer-one", CID: "cw-42",
		ScheduleWeekday: 1, ScheduleMinute: 480, Timezone: "Europe/Vienna",
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

	manager := New(repository, []byte("0123456789abcdef0123456789abcdef"), time.Second, slog.Default())
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
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0]["state"] != "open" || events[0]["cid"] != "cw-42" {
		t.Errorf("open event = %#v", events[0])
	}
	if events[1]["state"] != "closed" || events[1]["finding_key"] != events[0]["finding_key"] {
		t.Errorf("close event = %#v", events[1])
	}
	if events[1]["summary"] != events[0]["summary"] {
		t.Errorf("ticket summary changed across lifecycle: %q → %q", events[0]["summary"], events[1]["summary"])
	}
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "https", value: "https://hookwise.example/webhook/1"},
		{name: "internal http", value: "http://10.0.0.5:8080/webhook/1"},
		{name: "embedded credentials", value: "https://user:pass@example.com/hook", wantErr: true},
		{name: "unsupported scheme", value: "file:///tmp/hook", wantErr: true},
		{name: "relative", value: "/webhook/1", wantErr: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateEndpoint(testCase.value)
			if (err != nil) != testCase.wantErr {
				t.Errorf("validateEndpoint(%q) error = %v, wantErr %t", testCase.value, err, testCase.wantErr)
			}
		})
	}
}

package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"openvasconf/internal/customer"
)

func TestReconcileHookwiseOutboxMapsSeverityToConnectWisePriority(t *testing.T) {
	tests := []struct {
		name             string
		severity         float64
		expectedPriority string
	}{
		{name: "7.0 is high", severity: 7.0, expectedPriority: "P2-High"},
		{name: "8.49 is high", severity: 8.49, expectedPriority: "P2-High"},
		{name: "8.5 is critical", severity: 8.5, expectedPriority: "P1-Critical"},
		{name: "10.0 is critical", severity: 10.0, expectedPriority: "P1-Critical"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			repository := openTestStore(t)
			value := testCustomer(t, "connectwise-priority", []string{"10.59.0.1"})
			value.ConnectWiseCustomerName = "Acme Europe GmbH"
			if err := repository.CreateCustomer(t.Context(), value); err != nil {
				t.Fatalf("CreateCustomer() error = %v", err)
			}
			fixture := customerFixture{
				customerID: value.ID,
				scanEnd:    time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC),
			}
			saveTicketSnapshot(
				t,
				repository,
				fixture,
				"report-priority",
				fixture.scanEnd,
				testCase.severity,
			)
			if err := repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{
				Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher",
			}); err != nil {
				t.Fatalf("UpdateHookwiseSettings() error = %v", err)
			}
			if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
				t.Fatalf("ReconcileHookwiseOutbox() error = %v", err)
			}
			events, err := repository.PendingHookwiseEvents(t.Context(), 10)
			if err != nil || len(events) != 1 {
				t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
			}
			var payload struct {
				ConnectWiseCustomerName string  `json:"connectwise_customer_name"`
				Severity                string  `json:"severity"`
				SeveritySource          float64 `json:"severitysource"`
			}
			if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if payload.Severity != testCase.expectedPriority {
				t.Errorf("severity = %q, want %q", payload.Severity, testCase.expectedPriority)
			}
			if payload.SeveritySource != testCase.severity {
				t.Errorf("severitysource = %v, want %v", payload.SeveritySource, testCase.severity)
			}
			if payload.ConnectWiseCustomerName != value.ConnectWiseCustomerName {
				t.Errorf(
					"connectwise_customer_name = %q, want %q",
					payload.ConnectWiseCustomerName,
					value.ConnectWiseCustomerName,
				)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(events[0].Payload, &fields); err != nil {
				t.Fatalf("json.Unmarshal(fields) error = %v", err)
			}
			if _, found := fields["cid"]; found {
				t.Error("legacy cid field is still present in Hookwise payload")
			}
		})
	}
}

func TestRetryHookwiseFindingRearmsOnlyFailedEvent(t *testing.T) {
	repository, fixture, failed := hookwiseRetryTestFixture(t)
	if err := repository.MarkHookwiseFailed(t.Context(), failed, 503, "upstream unavailable"); err != nil {
		t.Fatalf("MarkHookwiseFailed() error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 0 {
		t.Fatalf("backed-off PendingHookwiseEvents() = %#v, %v", events, err)
	}

	if err := repository.RetryHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); err != nil {
		t.Fatalf("RetryHookwiseFinding() error = %v", err)
	}
	events, err = repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 || events[0].ID != failed.ID || events[0].Attempts != 1 {
		t.Fatalf("rearmed PendingHookwiseEvents() = %#v, %v", events, err)
	}
	if err := repository.RetryHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:missing",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RetryHookwiseFinding(non-failed) error = %v, want ErrNotFound", err)
	}
}

func TestRetryHookwiseFindingIgnoresUnfailedSiblingEvent(t *testing.T) {
	repository, fixture, openEvent := hookwiseRetryTestFixture(t)
	closeFinding(t, repository, fixture.customerID, RemediationResolved)
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("closing ReconcileHookwiseOutbox() error = %v", err)
	}
	if err := repository.MarkHookwiseFailed(t.Context(), openEvent, 503, "upstream unavailable"); err != nil {
		t.Fatalf("MarkHookwiseFailed() error = %v", err)
	}

	if err := repository.RetryHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); err != nil {
		t.Fatalf("RetryHookwiseFinding() error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
	}
	if events[0].ID != openEvent.ID || events[0].Attempts != 1 || events[1].Attempts != 0 {
		t.Fatalf("retried events = %#v", events)
	}
}

func TestRecreateHookwiseFindingQueuesNewOpenGeneration(t *testing.T) {
	repository, fixture, delivered := hookwiseRetryTestFixture(t)
	if err := repository.RecreateHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecreateHookwiseFinding(queued) error = %v, want ErrNotFound", err)
	}
	if err := repository.MarkHookwiseDelivered(t.Context(), delivered, 202); err != nil {
		t.Fatalf("MarkHookwiseDelivered() error = %v", err)
	}

	if err := repository.RecreateHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); err != nil {
		t.Fatalf("RecreateHookwiseFinding(open) error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
	}
	recreated := events[0]
	if recreated.ID == delivered.ID || recreated.Generation != delivered.Generation+1 ||
		recreated.EventType != "open" || recreated.Attempts != 0 {
		t.Fatalf("recreated event = %#v, delivered = %#v", recreated, delivered)
	}
	var payload struct {
		EventID string `json:"event_id"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(recreated.Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.EventID == "" || payload.State != "open" {
		t.Fatalf("recreated payload = %#v", payload)
	}
	findings, _, err := repository.CurrentFindings(t.Context(), FindingQuery{
		CustomerID: fixture.customerID,
	})
	if err != nil || len(findings) != 1 || findings[0].TicketState != "queued_open" {
		t.Fatalf("CurrentFindings() = %#v, %v", findings, err)
	}
	if err := repository.RecreateHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecreateHookwiseFinding(repeated) error = %v, want ErrNotFound", err)
	}
}

func hookwiseRetryTestFixture(t *testing.T) (*Store, customerFixture, HookwiseEvent) {
	t.Helper()
	repository := openTestStore(t)
	value := testCustomer(t, "ticket-retry", []string{"10.58.0.1"})
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	if err := repository.CreateCustomer(t.Context(), value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	fixture := customerFixture{
		customerID: value.ID,
		scanEnd:    time.Date(2026, 8, 28, 11, 0, 0, 0, time.UTC),
	}
	saveTicketSnapshot(t, repository, fixture, "report-retry", fixture.scanEnd, 8.5)
	if err := repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{
		Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher",
	}); err != nil {
		t.Fatalf("UpdateHookwiseSettings() error = %v", err)
	}
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("ReconcileHookwiseOutbox() error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("initial PendingHookwiseEvents() = %#v, %v", events, err)
	}
	return repository, fixture, events[0]
}

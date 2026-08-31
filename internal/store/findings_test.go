package store

import (
	"testing"
	"time"

	"openvasconf/internal/customer"
)

func TestCurrentFindingsAreTaskScopedAndSuppressible(t *testing.T) {
	ctx := t.Context()
	repository := openTestStore(t)
	value := testCustomer(t, "global-findings", []string{"10.55.0.1"})
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	if err := repository.CreateCustomer(ctx, value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	base := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	for index, taskID := range []string{"task-a", "task-b"} {
		snapshot := ReportSnapshot{
			ReportID: "task-report-" + taskID, TaskID: taskID, TaskName: taskID,
			CustomerID: value.ID, ScanStart: base, ScanEnd: base.Add(time.Duration(index) * time.Minute),
			Status: "Done",
		}
		finding := FindingSnapshot{
			Fingerprint: "v1:same", Title: "Same exact weakness", Host: "10.55.0.1",
			Port: "443/tcp", Severity: 8.1, Threat: "High",
		}
		if err := repository.SaveReportSnapshot(ctx, snapshot, []FindingSnapshot{finding}); err != nil {
			t.Fatalf("SaveReportSnapshot(%s) error = %v", taskID, err)
		}
	}

	rows, total, err := repository.CurrentFindings(ctx, FindingQuery{})
	if err != nil {
		t.Fatalf("CurrentFindings() error = %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("current findings = %d/%d, want 2/2", len(rows), total)
	}
	if err := repository.UpsertAnnotation(ctx, FindingAnnotation{
		CustomerID: value.ID, TaskID: "task-a", Fingerprint: "v1:same",
		Disposition: DispositionActive, Justification: "risk accepted by customer",
		Operator: "admin", RemediationState: RemediationWontFix,
	}); err != nil {
		t.Fatalf("UpsertAnnotation() error = %v", err)
	}
	active, activeTotal, err := repository.CurrentFindings(ctx, FindingQuery{})
	if err != nil || activeTotal != 1 || len(active) != 1 || active[0].TaskID != "task-b" {
		t.Fatalf("active findings = %#v total=%d error=%v", active, activeTotal, err)
	}
	suppressed, suppressedTotal, err := repository.CurrentFindings(ctx, FindingQuery{Scope: FindingScopeSuppressed})
	if err != nil || suppressedTotal != 1 || len(suppressed) != 1 || suppressed[0].TaskID != "task-a" {
		t.Fatalf("suppressed findings = %#v total=%d error=%v", suppressed, suppressedTotal, err)
	}
}

func TestSuccessfulNextSnapshotRemovesCurrentFinding(t *testing.T) {
	ctx := t.Context()
	repository := openTestStore(t)
	value := testCustomer(t, "finding-disappears", []string{"10.56.0.1"})
	if err := repository.CreateCustomer(ctx, value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	base := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	first := ReportSnapshot{ReportID: "present", TaskID: "task-1", TaskName: "task", CustomerID: value.ID, ScanStart: base, ScanEnd: base.Add(time.Hour), Status: "Done"}
	if err := repository.SaveReportSnapshot(ctx, first, []FindingSnapshot{{Fingerprint: "v1:gone", Title: "Gone", Host: "10.56.0.1", Severity: 9.0, Threat: "High"}}); err != nil {
		t.Fatalf("first SaveReportSnapshot() error = %v", err)
	}
	second := ReportSnapshot{ReportID: "absent", TaskID: "task-1", TaskName: "task", CustomerID: value.ID, ScanStart: base.Add(time.Hour), ScanEnd: base.Add(2 * time.Hour), Status: "Done"}
	if err := repository.SaveReportSnapshot(ctx, second, nil); err != nil {
		t.Fatalf("second SaveReportSnapshot() error = %v", err)
	}
	rows, total, err := repository.CurrentFindings(ctx, FindingQuery{})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("current findings after disappearance = %#v total=%d error=%v", rows, total, err)
	}
}

func TestHookwiseTicketCloseTransitions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *Store, customerFixture)
	}{
		{
			name: "severity downgrade",
			mutate: func(t *testing.T, repository *Store, fixture customerFixture) {
				t.Helper()
				saveTicketSnapshot(t, repository, fixture, "report-2", fixture.scanEnd.Add(time.Hour), 5.0)
			},
		},
		{
			name: "disappeared",
			mutate: func(t *testing.T, repository *Store, fixture customerFixture) {
				t.Helper()
				snapshot := ReportSnapshot{ReportID: "report-2", TaskID: "task-1", TaskName: "task", CustomerID: fixture.customerID, ScanStart: fixture.scanEnd, ScanEnd: fixture.scanEnd.Add(time.Hour), Status: "Done"}
				if err := repository.SaveReportSnapshot(t.Context(), snapshot, nil); err != nil {
					t.Fatalf("SaveReportSnapshot() error = %v", err)
				}
			},
		},
		{
			name: "resolved",
			mutate: func(t *testing.T, repository *Store, fixture customerFixture) {
				t.Helper()
				closeFinding(t, repository, fixture.customerID, RemediationResolved)
			},
		},
		{
			name: "wont fix",
			mutate: func(t *testing.T, repository *Store, fixture customerFixture) {
				t.Helper()
				closeFinding(t, repository, fixture.customerID, RemediationWontFix)
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			repository := openTestStore(t)
			value := testCustomer(t, "ticket-transition", []string{"10.57.0.1"})
			value.ConnectWiseCustomerName = "Acme Europe GmbH"
			if err := repository.CreateCustomer(t.Context(), value); err != nil {
				t.Fatalf("CreateCustomer() error = %v", err)
			}
			fixture := customerFixture{customerID: value.ID, scanEnd: time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC)}
			saveTicketSnapshot(t, repository, fixture, "report-1", fixture.scanEnd, 8.5)
			if err := repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher"}); err != nil {
				t.Fatalf("UpdateHookwiseSettings() error = %v", err)
			}
			if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
				t.Fatalf("initial ReconcileHookwiseOutbox() error = %v", err)
			}
			events, err := repository.PendingHookwiseEvents(t.Context(), 10)
			if err != nil || len(events) != 1 || events[0].EventType != "open" {
				t.Fatalf("open events = %#v, error = %v", events, err)
			}
			if err := repository.MarkHookwiseDelivered(t.Context(), events[0], 202); err != nil {
				t.Fatalf("MarkHookwiseDelivered() error = %v", err)
			}

			testCase.mutate(t, repository, fixture)
			if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
				t.Fatalf("closing ReconcileHookwiseOutbox() error = %v", err)
			}
			events, err = repository.PendingHookwiseEvents(t.Context(), 10)
			if err != nil || len(events) != 1 || events[0].EventType != "closed" {
				t.Fatalf("close events = %#v, error = %v", events, err)
			}
		})
	}
}

type customerFixture struct {
	customerID string
	scanEnd    time.Time
}

func saveTicketSnapshot(t *testing.T, repository *Store, fixture customerFixture, reportID string, scanEnd time.Time, severity float64) {
	t.Helper()
	snapshot := ReportSnapshot{ReportID: reportID, TaskID: "task-1", TaskName: "task", CustomerID: fixture.customerID, ScanStart: scanEnd.Add(-time.Hour), ScanEnd: scanEnd, Status: "Done"}
	finding := FindingSnapshot{Fingerprint: "v1:ticket", Title: "Ticket finding", Host: "10.57.0.1", Port: "443/tcp", Severity: severity, Threat: "High"}
	if err := repository.SaveReportSnapshot(t.Context(), snapshot, []FindingSnapshot{finding}); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}
}

func closeFinding(t *testing.T, repository *Store, customerID, state string) {
	t.Helper()
	if err := repository.UpsertAnnotation(t.Context(), FindingAnnotation{
		CustomerID: customerID, TaskID: "task-1", Fingerprint: "v1:ticket",
		Disposition: DispositionActive, Justification: "operator decision",
		Operator: "admin", RemediationState: state,
	}); err != nil {
		t.Fatalf("UpsertAnnotation() error = %v", err)
	}
}

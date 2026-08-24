package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStoredTimeTextSortsChronologicallyWithinSecond(t *testing.T) {
	t.Parallel()

	exact := time.Date(2026, 8, 22, 2, 45, 0, 0, time.UTC)
	fractional := exact.Add(time.Nanosecond)
	exactText := reportTimeText(exact)
	fractionalText := reportTimeText(fractional)
	if exactText >= fractionalText {
		t.Fatalf("stored times sort incorrectly: %q >= %q", exactText, fractionalText)
	}
	if len(exactText) != len(fractionalText) {
		t.Fatalf("stored time widths differ: %q and %q", exactText, fractionalText)
	}
	parsed, err := parseTime(fractionalText)
	if err != nil || !parsed.Equal(fractional) {
		t.Fatalf("parseTime(%q) = %v, %v", fractionalText, parsed, err)
	}
	if got := nullableTimeText(&exact); got != exactText {
		t.Errorf("nullableTimeText() = %#v, want %q", got, exactText)
	}
	zero := time.Time{}
	if got := nullableTimeText(&zero); got != nil {
		t.Errorf("nullableTimeText(zero) = %#v, want nil", got)
	}
}

func testSnapshot(customerID string) ReportSnapshot {
	return ReportSnapshot{
		ReportID:     "report-uuid-1",
		TaskID:       "task-uuid-1",
		TaskName:     "testcomp1_PrivateIP_Task1",
		CustomerID:   customerID,
		ScanStart:    time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC),
		ScanEnd:      time.Date(2026, 8, 22, 2, 45, 0, 0, time.UTC),
		Status:       "Done",
		SeverityMax:  9.8,
		CountHigh:    1,
		CountMedium:  0,
		CountLow:     0,
		CountLog:     1,
		FindingCount: 2,
	}
}

func testFindings() []FindingSnapshot {
	return []FindingSnapshot{
		{
			Fingerprint: "v1:aaa",
			NVTOID:      "1.3.6.1.4.1.25623.1.0.100001",
			Title:       "OpenSSH Weak Encryption",
			Host:        "10.1.0.5",
			Port:        "22/tcp",
			Severity:    9.8,
			Threat:      "High",
			QOD:         80,
			CVEs:        []string{"CVE-2021-1234", "CVE-2021-5678"},
			Remediation: "Update OpenSSH",
		},
		{
			Fingerprint: "v1:bbb",
			NVTOID:      "1.3.6.1.4.1.25623.1.0.100002",
			Title:       "nginx Version Detection",
			Host:        "10.1.0.6",
			Port:        "80/tcp",
			Severity:    0,
			Threat:      "Log",
			QOD:         95,
		},
	}
}

func TestReportSnapshotRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	customer := testCustomer(t, "reports", []string{"10.1.0.1"})
	if err := store.CreateCustomer(ctx, customer); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	if err := store.SaveReportSnapshot(ctx, testSnapshot(customer.ID), testFindings()); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}

	state, err := store.ReportImportState(ctx, "report-uuid-1")
	if err != nil || state != ImportStateImported {
		t.Fatalf("ReportImportState() = %q, %v", state, err)
	}

	listed, err := store.ListReportSnapshots(ctx, customer.ID, 10)
	if err != nil {
		t.Fatalf("ListReportSnapshots() error = %v", err)
	}
	if len(listed) != 1 || listed[0].CustomerName != "reports" ||
		listed[0].SeverityMax != 9.8 || listed[0].FindingCount != 2 {
		t.Fatalf("listed snapshots = %#v", listed)
	}
	if listed[0].ImportedAt == nil || listed[0].ScanEnd.Year() != 2026 {
		t.Errorf("snapshot times = %#v", listed[0])
	}

	other, err := store.ListReportSnapshots(ctx, "someone-else", 10)
	if err != nil || len(other) != 0 {
		t.Errorf("filtered snapshots = %#v, %v", other, err)
	}

	snapshot, err := store.ReportSnapshot(ctx, listed[0].ID)
	if err != nil {
		t.Fatalf("ReportSnapshot() error = %v", err)
	}
	if snapshot.ReportID != "report-uuid-1" || snapshot.TaskID != "task-uuid-1" {
		t.Errorf("snapshot = %#v", snapshot)
	}

	findings, err := store.ReportFindings(ctx, snapshot.ID)
	if err != nil {
		t.Fatalf("ReportFindings() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].Severity != 9.8 || findings[1].Severity != 0 {
		t.Errorf("findings not ordered by severity: %#v", findings)
	}
	if len(findings[0].CVEs) != 2 || findings[0].CVEs[1] != "CVE-2021-5678" {
		t.Errorf("finding cves = %#v", findings[0].CVEs)
	}
}

func TestSaveReportSnapshotRollbackLeavesNothing(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)

	snapshot := testSnapshot("customer-that-does-not-exist")
	if err := store.SaveReportSnapshot(ctx, snapshot, testFindings()); err == nil {
		t.Fatal("SaveReportSnapshot() error = nil, want foreign key failure")
	}
	if _, err := store.ReportImportState(ctx, snapshot.ReportID); !errors.Is(err, ErrNotFound) {
		t.Errorf("ReportImportState() error = %v, want ErrNotFound after rollback", err)
	}
	listed, err := store.ListReportSnapshots(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListReportSnapshots() error = %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("snapshots after rollback = %#v, want none", listed)
	}
}

func TestSaveReportSnapshotIdempotentReimport(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	snapshot := testSnapshot("")

	if err := store.SaveReportSnapshot(ctx, snapshot, testFindings()); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}
	replacement := []FindingSnapshot{{Fingerprint: "v1:zzz", Title: "should not appear"}}
	if err := store.SaveReportSnapshot(ctx, snapshot, replacement); err != nil {
		t.Fatalf("SaveReportSnapshot(reimport) error = %v", err)
	}

	listed, err := store.ListReportSnapshots(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListReportSnapshots() error = %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(listed))
	}
	findings, err := store.ReportFindings(ctx, listed[0].ID)
	if err != nil {
		t.Fatalf("ReportFindings() error = %v", err)
	}
	if len(findings) != 2 || findings[0].Fingerprint == "v1:zzz" {
		t.Errorf("findings after idempotent reimport = %#v", findings)
	}
}

func TestReportImportFailureRetriesAndReimport(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)

	for attempt := 1; attempt <= 2; attempt++ {
		if err := store.RecordReportImportFailure(
			ctx,
			"report-uuid-1",
			"task-uuid-1",
			"task",
			"",
			"diagnostic",
		); err != nil {
			t.Fatalf("RecordReportImportFailure() error = %v", err)
		}
	}

	pending, err := store.PendingReportRetries(ctx, 5)
	if err != nil {
		t.Fatalf("PendingReportRetries() error = %v", err)
	}
	if len(pending) != 1 || pending[0].ImportAttempts != 2 {
		t.Fatalf("pending retries = %#v", pending)
	}
	exhausted, err := store.PendingReportRetries(ctx, 2)
	if err != nil {
		t.Fatalf("PendingReportRetries(2) error = %v", err)
	}
	if len(exhausted) != 0 {
		t.Errorf("exhausted retries = %#v, want none", exhausted)
	}

	// Re-import after failure replaces the failed row with imported data.
	if err := store.SaveReportSnapshot(ctx, testSnapshot(""), testFindings()); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}
	state, err := store.ReportImportState(ctx, "report-uuid-1")
	if err != nil || state != ImportStateImported {
		t.Fatalf("ReportImportState() = %q, %v", state, err)
	}

	// A late failure must not downgrade an imported snapshot.
	if err := store.RecordReportImportFailure(
		ctx,
		"report-uuid-1",
		"task-uuid-1",
		"task",
		"",
		"late failure",
	); err != nil {
		t.Fatalf("RecordReportImportFailure(late) error = %v", err)
	}
	state, err = store.ReportImportState(ctx, "report-uuid-1")
	if err != nil || state != ImportStateImported {
		t.Errorf("ReportImportState(after late failure) = %q, %v", state, err)
	}

	stats, err := store.ReportImportStats(ctx)
	if err != nil {
		t.Fatalf("ReportImportStats() error = %v", err)
	}
	if stats.ImportedCount != 1 || stats.FailedCount != 0 || stats.LastImportedAt == nil {
		t.Errorf("import stats = %#v", stats)
	}
}

func TestCustomerForManagedTask(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := openTestStore(t)
	customer := testCustomer(t, "mapping", []string{"10.2.0.1"})
	if err := store.CreateCustomer(ctx, customer); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	if err := store.UpsertManagedResource(ctx, ManagedResource{
		CustomerID: customer.ID,
		Kind:       "task",
		Class:      "PrivateIP",
		Sequence:   1,
		GVMID:      "gvm-task-1",
		State:      "applied",
	}); err != nil {
		t.Fatalf("UpsertManagedResource() error = %v", err)
	}

	mapped, err := store.CustomerForManagedTask(ctx, "gvm-task-1")
	if err != nil || mapped != customer.ID {
		t.Fatalf("CustomerForManagedTask() = %q, %v", mapped, err)
	}
	if _, err := store.CustomerForManagedTask(ctx, "foreign-task"); !errors.Is(err, ErrNotFound) {
		t.Errorf("CustomerForManagedTask(foreign) error = %v, want ErrNotFound", err)
	}
}

package store

import (
	"errors"
	"testing"
	"time"

	"openvasconf/internal/customer"
)

func seedSnapshot(
	t *testing.T,
	store *Store,
	customerID,
	reportID string,
	scanEnd time.Time,
	fingerprints ...string,
) ReportSnapshot {
	t.Helper()
	ctx := t.Context()
	findings := make([]FindingSnapshot, 0, len(fingerprints))
	for index, fingerprint := range fingerprints {
		findings = append(findings, FindingSnapshot{
			Fingerprint: fingerprint,
			Title:       "finding " + fingerprint,
			Host:        "10.0.0.1",
			Severity:    float64(9 - index),
			Threat:      "High",
		})
	}
	snapshot := ReportSnapshot{
		ReportID:    reportID,
		TaskID:      "task-1",
		TaskName:    "task",
		CustomerID:  customerID,
		ScanStart:   scanEnd.Add(-time.Hour),
		ScanEnd:     scanEnd,
		Status:      "Done",
		SeverityMax: 9,
		CountHigh:   len(fingerprints),
	}
	if err := store.SaveReportSnapshot(ctx, snapshot, findings); err != nil {
		t.Fatalf("SaveReportSnapshot(%s) error = %v", reportID, err)
	}
	stored, err := store.ReportImportState(ctx, reportID)
	if err != nil || stored != ImportStateImported {
		t.Fatalf("seeded snapshot state = %q, %v", stored, err)
	}
	return snapshot
}

func snapshotByReportID(t *testing.T, store *Store, reportID string) ReportSnapshot {
	t.Helper()
	listed, err := store.ListReportSnapshots(t.Context(), "", 100)
	if err != nil {
		t.Fatalf("ListReportSnapshots() error = %v", err)
	}
	for _, snapshot := range listed {
		if snapshot.ReportID == reportID {
			return snapshot
		}
	}
	t.Fatalf("snapshot %q not found", reportID)
	return ReportSnapshot{}
}

func TestAnnotationUpsertAndPersistenceAcrossSnapshots(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	customer := testCustomer(t, "annotated", []string{"10.3.0.1"})
	if err := store.CreateCustomer(ctx, customer); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	due := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	expires := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	annotation := FindingAnnotation{
		CustomerID:       customer.ID,
		Fingerprint:      "v1:one",
		Disposition:      DispositionAcceptedRisk,
		Justification:    "accepted by security team",
		Operator:         "admin",
		RemediationState: RemediationInProgress,
		RemediationOwner: "ops-team",
		DueDate:          &due,
		ExpiresAt:        &expires,
	}
	if err := store.UpsertAnnotation(ctx, annotation); err != nil {
		t.Fatalf("UpsertAnnotation() error = %v", err)
	}

	got, err := store.Annotation(ctx, customer.ID, "v1:one")
	if err != nil {
		t.Fatalf("Annotation() error = %v", err)
	}
	if got.Disposition != DispositionAcceptedRisk || got.RemediationOwner != "ops-team" ||
		got.DueDate == nil || got.ExpiresAt == nil {
		t.Fatalf("annotation = %#v", got)
	}

	// Update via upsert: same key, new values.
	annotation.Disposition = DispositionFalsePositive
	annotation.RemediationState = RemediationWontFix
	annotation.DueDate = nil
	if err := store.UpsertAnnotation(ctx, annotation); err != nil {
		t.Fatalf("UpsertAnnotation(update) error = %v", err)
	}
	got, err = store.Annotation(ctx, customer.ID, "v1:one")
	if err != nil {
		t.Fatalf("Annotation(updated) error = %v", err)
	}
	if got.Disposition != DispositionFalsePositive ||
		got.RemediationState != RemediationWontFix || got.DueDate != nil {
		t.Fatalf("updated annotation = %#v", got)
	}

	// Importing further snapshots with the same fingerprint must not touch
	// the annotation.
	seedSnapshot(t, store, customer.ID, "report-a", time.Now().Add(-48*time.Hour), "v1:one")
	seedSnapshot(t, store, customer.ID, "report-b", time.Now().Add(-24*time.Hour), "v1:one")
	byCustomer, err := store.AnnotationsForCustomer(ctx, customer.ID)
	if err != nil {
		t.Fatalf("AnnotationsForCustomer() error = %v", err)
	}
	if len(byCustomer) != 1 || byCustomer["v1:one"].Disposition != DispositionFalsePositive {
		t.Errorf("annotations after snapshot imports = %#v", byCustomer)
	}

	if _, err := store.Annotation(ctx, customer.ID, "v1:missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Annotation(missing) error = %v, want ErrNotFound", err)
	}
}

func TestPreviousImportedSnapshotSelection(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	customer := testCustomer(t, "history", []string{"10.4.0.1"})
	if err := store.CreateCustomer(ctx, customer); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	seedSnapshot(t, store, customer.ID, "report-1", base.Add(24*time.Hour), "v1:a")
	seedSnapshot(t, store, customer.ID, "report-2", base.Add(48*time.Hour), "v1:a")
	seedSnapshot(t, store, customer.ID, "report-3", base.Add(72*time.Hour), "v1:a")

	first := snapshotByReportID(t, store, "report-1")
	if _, err := store.PreviousImportedSnapshot(ctx, first); !errors.Is(err, ErrNotFound) {
		t.Errorf("PreviousImportedSnapshot(first) error = %v, want ErrNotFound", err)
	}

	third := snapshotByReportID(t, store, "report-3")
	previous, err := store.PreviousImportedSnapshot(ctx, third)
	if err != nil {
		t.Fatalf("PreviousImportedSnapshot() error = %v", err)
	}
	if previous.ReportID != "report-2" {
		t.Errorf("previous = %q, want report-2", previous.ReportID)
	}

	// A failed snapshot between imported ones must be skipped.
	if err := store.RecordReportImportFailure(ctx, "report-failed", "task-1", "task", customer.ID, "boom"); err != nil {
		t.Fatalf("RecordReportImportFailure() error = %v", err)
	}
	previous, err = store.PreviousImportedSnapshot(ctx, third)
	if err != nil || previous.ReportID != "report-2" {
		t.Errorf("previous with failed row = %q, %v", previous.ReportID, err)
	}
}

func TestFirstSeenGroupedQuery(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	customer := testCustomer(t, "firstseen", []string{"10.5.0.1"})
	if err := store.CreateCustomer(ctx, customer); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	seedSnapshot(t, store, customer.ID, "report-1", base.Add(24*time.Hour), "v1:old", "v1:shared")
	seedSnapshot(t, store, customer.ID, "report-2", base.Add(48*time.Hour), "v1:shared", "v1:new")

	seen, err := store.FirstSeen(ctx, customer.ID, []string{"v1:old", "v1:shared", "v1:new", "v1:unknown"})
	if err != nil {
		t.Fatalf("FirstSeen() error = %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("first-seen entries = %d, want 3", len(seen))
	}
	if !seen["v1:old"].Equal(base.Add(24 * time.Hour)) {
		t.Errorf("v1:old first seen = %v", seen["v1:old"])
	}
	if !seen["v1:shared"].Equal(base.Add(24 * time.Hour)) {
		t.Errorf("v1:shared first seen = %v, want the earlier snapshot", seen["v1:shared"])
	}
	if !seen["v1:new"].Equal(base.Add(48 * time.Hour)) {
		t.Errorf("v1:new first seen = %v", seen["v1:new"])
	}
}

func TestReportTrendOrderingAndLimit(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	customer := testCustomer(t, "trend", []string{"10.6.0.1"})
	if err := store.CreateCustomer(ctx, customer); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for index := range 5 {
		seedSnapshot(
			t,
			store,
			customer.ID,
			"report-"+string(rune('a'+index)),
			base.Add(time.Duration(index+1)*24*time.Hour),
			"v1:x",
		)
	}

	trend, err := store.ReportTrend(ctx, customer.ID, 3)
	if err != nil {
		t.Fatalf("ReportTrend() error = %v", err)
	}
	if len(trend) != 3 {
		t.Fatalf("trend length = %d, want 3", len(trend))
	}
	if trend[0].ReportID != "report-c" || trend[2].ReportID != "report-e" {
		t.Errorf("trend order = %q → %q, want report-c → report-e", trend[0].ReportID, trend[2].ReportID)
	}
	for index := 1; index < len(trend); index++ {
		if trend[index].ScanEnd.Before(trend[index-1].ScanEnd) {
			t.Errorf("trend not oldest-first: %#v", trend)
		}
	}
}

func TestSettingsSLARoundTrip(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	settings, err := store.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings() error = %v", err)
	}
	if settings.SLA.CriticalDays != 7 || settings.SLA.HighDays != 14 ||
		settings.SLA.MediumDays != 30 || settings.SLA.LowDays != 90 {
		t.Fatalf("default SLA = %#v", settings.SLA)
	}

	settings.SLA = customer.SLAPolicy{CriticalDays: 3, HighDays: 10, MediumDays: 20, LowDays: 40}
	if err := store.UpdateSettings(ctx, settings); err != nil {
		t.Fatalf("UpdateSettings() error = %v", err)
	}
	updated, err := store.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings(updated) error = %v", err)
	}
	if updated.SLA.CriticalDays != 3 || updated.SLA.LowDays != 40 {
		t.Errorf("updated SLA = %#v", updated.SLA)
	}

	settings.SLA = customer.SLAPolicy{}
	if err := store.UpdateSettings(ctx, settings); err != nil {
		t.Fatalf("UpdateSettings(zero SLA) error = %v", err)
	}
	updated, err = store.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings(zero SLA) error = %v", err)
	}
	if updated.SLA != (customer.SLAPolicy{}) {
		t.Errorf("zero SLA = %#v, want explicit due-immediately values", updated.SLA)
	}

	settings.SLA.CriticalDays = -1
	if err := store.UpdateSettings(ctx, settings); err == nil {
		t.Error("UpdateSettings(negative SLA) error = nil, want validation error")
	}
}

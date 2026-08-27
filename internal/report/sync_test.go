package report

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
)

type recordedFailure struct {
	reportID   string
	taskID     string
	customerID string
	diagnostic string
}

type fakeReportStore struct {
	mu            sync.Mutex
	states        map[string]string
	attempts      map[string]int
	customers     map[string]string
	snapshots     map[string]store.ReportSnapshot
	findings      map[string][]store.FindingSnapshot
	failures      []recordedFailure
	taskCustomers map[string]string
	resetCount    int
	deleted       []string
}

func (f *fakeReportStore) DeleteFailedReportImport(_ context.Context, reportID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states[reportID] == store.ImportStateFailed {
		delete(f.states, reportID)
		delete(f.attempts, reportID)
		delete(f.customers, reportID)
		f.deleted = append(f.deleted, reportID)
	}
	return nil
}

func (f *fakeReportStore) ResetFailedReportImports(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resetCount++
	for reportID, state := range f.states {
		if state == store.ImportStateFailed {
			f.attempts[reportID] = 0
		}
	}
	return nil
}

func newFakeReportStore() *fakeReportStore {
	return &fakeReportStore{
		states:        make(map[string]string),
		attempts:      make(map[string]int),
		customers:     make(map[string]string),
		snapshots:     make(map[string]store.ReportSnapshot),
		findings:      make(map[string][]store.FindingSnapshot),
		taskCustomers: make(map[string]string),
	}
}

func (f *fakeReportStore) ReportImportState(_ context.Context, reportID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, found := f.states[reportID]
	if !found {
		return "", store.ErrNotFound
	}
	return state, nil
}

func (f *fakeReportStore) SaveReportSnapshot(
	_ context.Context,
	snapshot store.ReportSnapshot,
	findings []store.FindingSnapshot,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states[snapshot.ReportID] == store.ImportStateImported {
		return nil
	}
	f.states[snapshot.ReportID] = store.ImportStateImported
	f.snapshots[snapshot.ReportID] = snapshot
	f.findings[snapshot.ReportID] = findings
	return nil
}

func (f *fakeReportStore) RecordReportImportFailure(
	_ context.Context,
	reportID, taskID, taskName, customerID, diagnostic string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states[reportID] == store.ImportStateImported {
		return nil
	}
	f.states[reportID] = store.ImportStateFailed
	f.attempts[reportID]++
	f.customers[reportID] = customerID
	f.failures = append(f.failures, recordedFailure{
		reportID:   reportID,
		taskID:     taskID,
		customerID: customerID,
		diagnostic: diagnostic,
	})
	return nil
}

func (f *fakeReportStore) PendingReportRetries(
	_ context.Context,
	maxAttempts int,
) ([]store.ReportSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]store.ReportSnapshot, 0)
	for reportID, state := range f.states {
		if state != store.ImportStateFailed || f.attempts[reportID] >= maxAttempts {
			continue
		}
		result = append(result, store.ReportSnapshot{
			ReportID:   reportID,
			CustomerID: f.customers[reportID],
		})
	}
	return result, nil
}

func (f *fakeReportStore) CustomerForManagedTask(_ context.Context, gvmTaskID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	customerID, found := f.taskCustomers[gvmTaskID]
	if !found {
		return "", store.ErrNotFound
	}
	return customerID, nil
}

func (f *fakeReportStore) ReportImportStats(context.Context) (store.ReportImportStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stats := store.ReportImportStats{}
	for _, state := range f.states {
		switch state {
		case store.ImportStateImported:
			stats.ImportedCount++
		case store.ImportStateFailed:
			stats.FailedCount++
		}
	}
	return stats, nil
}

type fakeReportGMP struct {
	mu        sync.Mutex
	tasks     []gmp.TaskStatus
	reports   map[string]gmp.ReportDetails
	reportErr map[string]error
	fetched   []string
}

func (f *fakeReportGMP) Tasks(context.Context) ([]gmp.TaskStatus, error) {
	return f.tasks, nil
}

func (f *fakeReportGMP) Report(
	_ context.Context,
	reportID string,
	_ gmp.ReportLimits,
) (gmp.ReportDetails, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetched = append(f.fetched, reportID)
	if err, failed := f.reportErr[reportID]; failed {
		return gmp.ReportDetails{}, err
	}
	report, found := f.reports[reportID]
	if !found {
		return gmp.ReportDetails{}, fmt.Errorf("report %q missing", reportID)
	}
	return report, nil
}

func (f *fakeReportGMP) fetchedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.fetched)
}

func newTestSyncer(repository *fakeReportStore, greenbone *fakeReportGMP) *Syncer {
	return NewSyncer(
		repository,
		greenbone,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		2*time.Minute,
		Limits{MaxFindings: 1000, MaxXMLBytes: 1 << 20, Concurrency: 2},
	)
}

func taskWithReport(taskID, reportID, status string) gmp.TaskStatus {
	return gmp.TaskStatus{
		ID:   taskID,
		Name: "task " + taskID,
		LastReport: &gmp.ReportStatus{
			ID:      reportID,
			Status:  status,
			ScanEnd: time.Now(),
		},
	}
}

func TestSyncerDiscoversAndImports(t *testing.T) {
	t.Parallel()

	repository := newFakeReportStore()
	repository.taskCustomers["gvm-task-1"] = "customer-1"
	repository.states["report-imported"] = store.ImportStateImported
	greenbone := &fakeReportGMP{
		tasks: []gmp.TaskStatus{
			taskWithReport("gvm-task-1", "report-new", "Done"),
			taskWithReport("gvm-task-1", "report-imported", "Done"),
			taskWithReport("gvm-foreign", "report-foreign", "Done"),
			taskWithReport("gvm-task-1", "report-running", "Running"),
			{ID: "gvm-task-1", Name: "no report yet"},
		},
		reports: map[string]gmp.ReportDetails{
			"report-new": {
				ID:       "report-new",
				TaskID:   "gvm-task-1",
				TaskName: "task gvm-task-1",
				Status:   "Done",
				ScanEnd:  time.Date(2026, 8, 22, 3, 0, 0, 0, time.UTC),
				Results: []gmp.ReportResult{{
					NVTOID:   "oid-1",
					Host:     "10.0.0.1",
					Port:     "22/tcp",
					Threat:   "High",
					Severity: 9.8,
				}},
			},
		},
	}
	syncer := newTestSyncer(repository, greenbone)

	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatalf("SyncOnce() error = %v", err)
	}

	snapshot, found := repository.snapshots["report-new"]
	if !found {
		t.Fatal("report-new was not imported")
	}
	if snapshot.CustomerID != "customer-1" || snapshot.TaskID != "gvm-task-1" {
		t.Errorf("snapshot mapping = %#v", snapshot)
	}
	if len(repository.findings["report-new"]) != 1 {
		t.Errorf("findings = %#v", repository.findings["report-new"])
	}
	if _, found := repository.snapshots["report-foreign"]; found {
		t.Error("foreign report must not be imported")
	}
	if greenbone.fetchedCount() != 1 {
		t.Errorf("fetched = %d, want exactly one new report", greenbone.fetchedCount())
	}
}

func TestSyncerReprocessingIsIdempotent(t *testing.T) {
	t.Parallel()

	repository := newFakeReportStore()
	repository.taskCustomers["gvm-task-1"] = "customer-1"
	greenbone := &fakeReportGMP{
		tasks: []gmp.TaskStatus{taskWithReport("gvm-task-1", "report-new", "Done")},
		reports: map[string]gmp.ReportDetails{
			"report-new": {
				ID:      "report-new",
				Status:  "Done",
				Results: []gmp.ReportResult{{NVTOID: "oid-1", Host: "10.0.0.1", Severity: 5}},
			},
		},
	}
	syncer := newTestSyncer(repository, greenbone)

	ctx := t.Context()
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(first) error = %v", err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(second) error = %v", err)
	}
	if greenbone.fetchedCount() != 1 {
		t.Errorf("fetched = %d, want 1 (already imported reports are skipped)", greenbone.fetchedCount())
	}
	if len(repository.findings["report-new"]) != 1 {
		t.Errorf("findings duplicated: %#v", repository.findings["report-new"])
	}
}

func TestSyncerFailureBackoffAndSanitizedDiagnostic(t *testing.T) {
	t.Parallel()

	repository := newFakeReportStore()
	repository.taskCustomers["gvm-task-1"] = "customer-1"
	payload := "gmp failure " + strings.Repeat("<result>secret-payload</result> ", 100)
	greenbone := &fakeReportGMP{
		tasks:     []gmp.TaskStatus{taskWithReport("gvm-task-1", "report-bad", "Done")},
		reportErr: map[string]error{"report-bad": errors.New(payload)},
	}
	syncer := newTestSyncer(repository, greenbone)
	ctx := t.Context()

	if err := syncer.SyncOnce(ctx); err == nil {
		t.Fatal("SyncOnce() error = nil, want failed import")
	}
	if len(repository.failures) != 1 {
		t.Fatalf("failures = %#v", repository.failures)
	}
	failure := repository.failures[0]
	if failure.customerID != "customer-1" {
		t.Errorf("failure customer = %q", failure.customerID)
	}
	if len([]rune(failure.diagnostic)) > maxDiagnosticLength {
		t.Errorf("diagnostic length = %d, want <= %d", len(failure.diagnostic), maxDiagnosticLength)
	}
	if strings.Contains(failure.diagnostic, strings.Repeat("<result>", 3)) {
		t.Errorf("diagnostic contains raw payload repetition: %q", failure.diagnostic)
	}

	// The exponential backoff suppresses an immediate retry.
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(backoff) error = %v, want nil (report not due yet)", err)
	}
	if greenbone.fetchedCount() != 1 {
		t.Errorf("fetched = %d, want 1 while the backoff window is open", greenbone.fetchedCount())
	}

	// Once the store-level attempt budget is exhausted the report is left alone.
	repository.attempts["report-bad"] = maxImportAttempts
	syncer.clearRetry("report-bad")
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(exhausted) error = %v, want nil (nothing to do)", err)
	}
	if greenbone.fetchedCount() != 1 {
		t.Errorf("fetched = %d, want 1 after the attempt budget is exhausted", greenbone.fetchedCount())
	}
}

func TestSyncerManualTriggerRetriesExhaustedReports(t *testing.T) {
	t.Parallel()

	repository := newFakeReportStore()
	repository.states["report-exhausted"] = store.ImportStateFailed
	repository.attempts["report-exhausted"] = maxImportAttempts
	repository.customers["report-exhausted"] = "customer-1"
	greenbone := &fakeReportGMP{
		reports: map[string]gmp.ReportDetails{
			"report-exhausted": {ID: "report-exhausted", Status: "Done"},
		},
	}
	syncer := newTestSyncer(repository, greenbone)
	syncer.nextRetry["report-exhausted"] = time.Now().Add(time.Hour)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go syncer.Run(ctx)
	syncer.Trigger()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		repository.mu.Lock()
		state := repository.states["report-exhausted"]
		resetCount := repository.resetCount
		repository.mu.Unlock()
		if state == store.ImportStateImported && resetCount == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("manual trigger did not requeue and import the exhausted report")
}

func TestSyncerRemovesMissingFailedRetry(t *testing.T) {
	t.Parallel()

	repository := newFakeReportStore()
	repository.states["report-stale"] = store.ImportStateFailed
	repository.attempts["report-stale"] = 1
	repository.customers["report-stale"] = "customer-1"
	greenbone := &fakeReportGMP{
		reportErr: map[string]error{
			"report-stale": &gmp.ProtocolError{
				Command:    "get_reports",
				Status:     "404",
				StatusText: "Failed to find report",
			},
		},
	}
	syncer := newTestSyncer(repository, greenbone)

	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatalf("SyncOnce() error = %v", err)
	}
	if len(repository.deleted) != 1 || repository.deleted[0] != "report-stale" {
		t.Fatalf("deleted reports = %#v, want report-stale", repository.deleted)
	}
	if _, err := repository.ReportImportState(t.Context(), "report-stale"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReportImportState() error = %v, want ErrNotFound", err)
	}
}

func TestSyncerKeepsMissingCurrentReportVisible(t *testing.T) {
	t.Parallel()

	repository := newFakeReportStore()
	repository.taskCustomers["task-1"] = "customer-1"
	greenbone := &fakeReportGMP{
		tasks: []gmp.TaskStatus{taskWithReport("task-1", "report-current", "Done")},
		reportErr: map[string]error{
			"report-current": &gmp.ProtocolError{
				Command:    "get_reports",
				Status:     "404",
				StatusText: "Failed to find report",
			},
		},
	}
	syncer := newTestSyncer(repository, greenbone)

	if err := syncer.SyncOnce(t.Context()); err == nil {
		t.Fatal("SyncOnce() error = nil, want current missing report failure")
	}
	if len(repository.deleted) != 0 {
		t.Fatalf("deleted reports = %#v, want none", repository.deleted)
	}
	state, err := repository.ReportImportState(t.Context(), "report-current")
	if err != nil || state != store.ImportStateFailed {
		t.Fatalf("ReportImportState() = %q, %v, want failed", state, err)
	}
}

func TestSyncerAuthFailureAbortsCycle(t *testing.T) {
	t.Parallel()

	repository := newFakeReportStore()
	repository.taskCustomers["gvm-task-1"] = "customer-1"
	greenbone := &fakeReportGMP{
		tasks: []gmp.TaskStatus{taskWithReport("gvm-task-1", "report-auth", "Done")},
		reportErr: map[string]error{
			"report-auth": &gmp.ProtocolError{
				Command:    "authenticate",
				Status:     "401",
				StatusText: "Authentication failed",
			},
		},
	}
	syncer := newTestSyncer(repository, greenbone)

	err := syncer.SyncOnce(t.Context())
	var protocolError *gmp.ProtocolError
	if !errors.As(err, &protocolError) {
		t.Fatalf("SyncOnce() error = %v, want protocol error", err)
	}
	if len(repository.failures) != 0 {
		t.Errorf("auth failure must not record a per-report failure: %#v", repository.failures)
	}
	state, _, _, _ := syncer.ReportHealth(t.Context())
	if state != "degraded" {
		t.Errorf("health after auth failure = %q, want degraded", state)
	}
}

func TestSyncerReportHealth(t *testing.T) {
	t.Parallel()

	repository := newFakeReportStore()
	repository.taskCustomers["gvm-task-1"] = "customer-1"
	greenbone := &fakeReportGMP{
		tasks: []gmp.TaskStatus{taskWithReport("gvm-task-1", "report-new", "Done")},
		reports: map[string]gmp.ReportDetails{
			"report-new": {ID: "report-new", Status: "Done"},
		},
	}
	syncer := newTestSyncer(repository, greenbone)

	state, _, _, link := syncer.ReportHealth(t.Context())
	if state != "unknown" || link != "/reports" {
		t.Errorf("health before first cycle = %q link %q, want unknown /reports", state, link)
	}

	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatalf("SyncOnce() error = %v", err)
	}
	state, detail, _, _ := syncer.ReportHealth(t.Context())
	if state != "ok" {
		t.Errorf("health after successful cycle = %q (%s), want ok", state, detail)
	}

	repository.states["report-broken"] = store.ImportStateFailed
	state, detail, guidance, _ := syncer.ReportHealth(t.Context())
	if state != "degraded" || guidance == "" {
		t.Errorf("health with failed imports = %q (%s), want degraded with guidance", state, detail)
	}
}

package updater

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testImageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type memoryStateStore struct {
	mu    sync.Mutex
	state persistentState
}

func (s *memoryStateStore) Load() (persistentState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state), nil
}

func (s *memoryStateStore) Save(state persistentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = cloneState(state)
	return nil
}

type fakeRuntime struct {
	mu           sync.Mutex
	before       []Image
	after        []Image
	appliedFeed  bool
	applied      bool
	rolledBack   bool
	backup       bool
	rollbackPath string
}

func (r *fakeRuntime) Validate(context.Context) error { return nil }

func (r *fakeRuntime) Snapshot(context.Context, []string) ([]Image, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Image(nil), r.before...), nil
}

func (r *fakeRuntime) ResolvedSnapshot(context.Context, []string) ([]Image, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Image(nil), r.after...), nil
}

func (r *fakeRuntime) PullFeed(context.Context) error  { return nil }
func (r *fakeRuntime) PullStack(context.Context) error { return nil }

func (r *fakeRuntime) ApplyFeed(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.appliedFeed = true
	return nil
}

func (r *fakeRuntime) ApplyStack(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applied = true
	return nil
}

func (r *fakeRuntime) Backup(context.Context, string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backup = true
	return "/backups/test.dump", nil
}

func (r *fakeRuntime) Rollback(_ context.Context, _ []Image, backupPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rolledBack = true
	r.rollbackPath = backupPath
	return nil
}

func (r *fakeRuntime) PruneBackups(int, string) error { return nil }
func (r *fakeRuntime) FeedServices() []string         { return []string{"vulnerability-tests"} }
func (r *fakeRuntime) StackServices() []string        { return []string{"gvmd"} }

func (r *fakeRuntime) state() (appliedFeed, applied, rolledBack, backup bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.appliedFeed, r.applied, r.rolledBack, r.backup
}

func (r *fakeRuntime) restoredBackup() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rollbackPath
}

type fakeScanner struct {
	mu          sync.Mutex
	runtime     *fakeRuntime
	activeScans int
	beforeFeed  Feed
	afterFeed   Feed
	failApplied bool
}

func (s *fakeScanner) Ping(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.failApplied || s.runtime == nil {
		return nil
	}
	_, applied, rolledBack, _ := s.runtime.state()
	if applied && !rolledBack {
		return errors.New("scanner unavailable after apply")
	}
	return nil
}

func (s *fakeScanner) Feeds(context.Context) ([]Feed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtime != nil {
		appliedFeed, _, _, _ := s.runtime.state()
		if appliedFeed {
			return []Feed{s.afterFeed}, nil
		}
	}
	return []Feed{s.beforeFeed}, nil
}

func (s *fakeScanner) ActiveScans(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeScans, nil
}

func TestPolicyValidationRejectsOvernightMaintenance(t *testing.T) {
	policy := DefaultPolicy("Europe/Vienna")
	policy.StackStartMinute = 23 * 60
	policy.StackWindowMinutes = 120
	if err := policy.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want overnight-window error")
	}
}

func TestControllerRefreshesChangedFeeds(t *testing.T) {
	runtime := &fakeRuntime{
		before: []Image{{Service: "vulnerability-tests", ID: testImageID}},
		after:  []Image{{Service: "vulnerability-tests", ID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
	}
	scanner := &fakeScanner{
		runtime:    runtime,
		beforeFeed: Feed{Name: "NVT", Version: "1", UpdatedAt: time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)},
		afterFeed:  Feed{Name: "NVT", Version: "2", UpdatedAt: time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)},
	}
	controller := newTestController(t, runtime, scanner, time.Now)
	operation, err := controller.Trigger(t.Context(), KindFeed, TriggerRequest{
		IdempotencyKey: "manual-feed-test", Trigger: TriggerAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if operation.PhaseStartedAt.IsZero() || !operation.PhaseStartedAt.Equal(operation.StartedAt) {
		t.Fatalf("queued phase start = %s, operation start = %s", operation.PhaseStartedAt, operation.StartedAt)
	}
	finished := waitForTerminal(t, controller, operation.ID)
	if finished.PhaseStartedAt.IsZero() {
		t.Fatal("finished operation has no phase start")
	}
	if finished.State != StateSucceeded {
		t.Fatalf("state = %q, want %q: %s", finished.State, StateSucceeded, finished.Detail)
	}
	appliedFeed, _, _, _ := runtime.state()
	if !appliedFeed {
		t.Fatal("feed services were not applied")
	}
}

func TestControllerDefersScheduledStackWhileScansRemainActive(t *testing.T) {
	now := time.Date(2026, 8, 23, 7, 0, 0, 0, time.UTC) // Sunday, after the default window.
	runtime := &fakeRuntime{}
	scanner := &fakeScanner{runtime: runtime, activeScans: 2}
	controller := newTestController(t, runtime, scanner, func() time.Time { return now })
	operation, err := controller.Trigger(t.Context(), KindStack, TriggerRequest{
		IdempotencyKey: "scheduled-stack-test", Trigger: TriggerScheduled,
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := waitForTerminal(t, controller, operation.ID)
	if finished.State != StateCancelled {
		t.Fatalf("state = %q, want %q", finished.State, StateCancelled)
	}
	_, applied, _, backup := runtime.state()
	if applied || backup {
		t.Fatal("deferred stack operation modified the runtime")
	}
}

func TestControllerRollsBackAndPausesAfterFailedVerification(t *testing.T) {
	runtime := &fakeRuntime{
		before: []Image{{
			Service: "gvmd", Repository: approvedRegistryPrefix + "gvmd", Tag: "stable", ID: testImageID,
		}},
		after: []Image{{
			Service: "gvmd", Repository: approvedRegistryPrefix + "gvmd", Tag: "stable",
			ID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		}},
	}
	scanner := &fakeScanner{
		runtime: runtime, failApplied: true,
		beforeFeed: Feed{Name: "NVT", Version: "1"},
		afterFeed:  Feed{Name: "NVT", Version: "1"},
	}
	controller := newTestController(t, runtime, scanner, time.Now)
	operation, err := controller.Trigger(t.Context(), KindStack, TriggerRequest{
		IdempotencyKey: "manual-stack-test", Trigger: TriggerAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := waitForTerminal(t, controller, operation.ID)
	if finished.State != StateRolledBack {
		t.Fatalf("state = %q, want %q: %s", finished.State, StateRolledBack, finished.Detail)
	}
	_, applied, rolledBack, backup := runtime.state()
	if !applied || !rolledBack || !backup {
		t.Fatalf("runtime applied=%t rolledBack=%t backup=%t", applied, rolledBack, backup)
	}
	status, err := controller.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.AutomationPaused {
		t.Fatal("automation was not paused after rollback")
	}
}

func TestControllerRecoversInterruptedStackWithPersistedBackup(t *testing.T) {
	t.Parallel()

	const backupPath = "/backups/restart.dump"
	policy := DefaultPolicy("UTC")
	policy.FeedEnabled = false
	policy.StackEnabled = false
	stateStore := &memoryStateStore{state: persistentState{
		Policy: policy,
		Active: &Operation{
			ID:           "interrupted-stack",
			Kind:         KindStack,
			Trigger:      TriggerAdmin,
			State:        StateRunning,
			Phase:        "applying",
			StartedAt:    time.Now().UTC(),
			ImagesBefore: []Image{{Service: "gvmd", ID: testImageID}},
		},
		BackupPath:  backupPath,
		Idempotency: map[string]string{},
	}}
	runtime := &fakeRuntime{}
	controller, err := NewController(ControllerOptions{
		Runtime:          runtime,
		Scanner:          &fakeScanner{runtime: runtime},
		Store:            stateStore,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		DefaultPolicy:    policy,
		ScheduleInterval: time.Hour,
		PollInterval:     time.Millisecond,
		OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := controller.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	waitForTerminal(t, controller, "interrupted-stack")
	cancel()
	controller.Close()

	if got := runtime.restoredBackup(); got != backupPath {
		t.Errorf("Rollback() backup path = %q, want %q", got, backupPath)
	}
}

func TestFileStateStorePersistsBackupPathOutsideOperation(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	store, err := NewFileStateStore(filepath.Join(directory, "updater.json"))
	if err != nil {
		t.Fatal(err)
	}
	const backupPath = "/backups/persisted.dump"
	state := persistentState{
		Active:     &Operation{ID: "operation", Backup: "/backups/not-serialized.dump"},
		BackupPath: backupPath,
	}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(directory, "updater.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"backup_path": "/backups/persisted.dump"`) {
		t.Fatalf("state file does not contain persisted backup path: %s", contents)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BackupPath != backupPath {
		t.Errorf("loaded backup path = %q, want %q", loaded.BackupPath, backupPath)
	}
	if loaded.Active == nil || loaded.Active.Backup != "" {
		t.Errorf("operation backup was unexpectedly serialized: %#v", loaded.Active)
	}
}

func TestTriggerIsIdempotent(t *testing.T) {
	runtime := &fakeRuntime{}
	scanner := &fakeScanner{runtime: runtime}
	controller := newTestController(t, runtime, scanner, time.Now)
	request := TriggerRequest{IdempotencyKey: "same-request", Trigger: TriggerAdmin}
	first, err := controller.Trigger(t.Context(), KindCheck, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := controller.Trigger(t.Context(), KindCheck, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("duplicate request IDs = %q and %q", first.ID, second.ID)
	}
}

func newTestController(
	t *testing.T,
	runtime *fakeRuntime,
	scanner *fakeScanner,
	now func() time.Time,
) *Controller {
	t.Helper()
	policy := DefaultPolicy("UTC")
	policy.FeedEnabled = false
	policy.StackEnabled = false
	controller, err := NewController(ControllerOptions{
		Runtime:          runtime,
		Scanner:          scanner,
		Store:            &memoryStateStore{},
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		DefaultPolicy:    policy,
		ScheduleInterval: time.Hour,
		PollInterval:     time.Millisecond,
		OperationTimeout: 20 * time.Millisecond,
		Now:              now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := controller.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		controller.Close()
	})
	return controller
}

func waitForTerminal(t *testing.T, controller *Controller, operationID string) Operation {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, err := controller.Status(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if status.Active != nil && status.Active.ID == operationID && status.Active.Terminal() {
			return *status.Active
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("operation did not finish")
	return Operation{}
}

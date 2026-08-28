package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestStoreReconcileRunLifecycle(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	database := openTestStore(t)
	value := testCustomer(t, "reconcile-run", []string{"10.30.0.0/24"})
	if err := database.CreateCustomer(ctx, value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	runID, err := database.BeginReconcileRun(ctx, value.ID)
	if err != nil {
		t.Fatalf("BeginReconcileRun() error = %v", err)
	}
	retryAt := time.Now().UTC().Add(time.Minute)
	progress := ReconcileProgress{
		Phase: "resources", CurrentOperation: "creating target",
		CompletedOperations: 2, TotalOperations: 5, Attempt: 2, MaxAttempts: 4,
		NextRetryAt: &retryAt, SafeError: "retrying", TechnicalError: "temporary failure",
	}
	if err := database.UpdateReconcileProgress(ctx, runID, value.ID, progress); err != nil {
		t.Fatalf("UpdateReconcileProgress() error = %v", err)
	}
	if err := database.AddReconcileOperation(ctx, ReconcileOperation{
		RunID: runID, CustomerID: value.ID, Action: "create", ResourceKind: "target",
		ResourceName: "target-1", Status: "succeeded", Detail: "created",
		Duration: 1250 * time.Millisecond,
	}); err != nil {
		t.Fatalf("AddReconcileOperation() error = %v", err)
	}
	if err := database.FinishReconcileRun(ctx, runID, nil); err != nil {
		t.Fatalf("FinishReconcileRun() error = %v", err)
	}

	runs, err := database.ReconcileRuns(ctx, value.ID, 0)
	if err != nil {
		t.Fatalf("ReconcileRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("run count = %d, want 1", len(runs))
	}
	got := runs[0]
	if got.ID != runID || got.Status != "succeeded" || got.FinishedAt == nil || got.Phase != progress.Phase {
		t.Errorf("run = %#v", got)
	}
	if len(got.Operations) != 1 || got.Operations[0].Duration != 1250*time.Millisecond {
		t.Errorf("operations = %#v", got.Operations)
	}
	updated, err := database.Customer(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.LastSuccessfulReconcile == nil || updated.Reconciliation.Phase != "complete" || updated.Reconciliation.NextRetryAt != nil {
		t.Errorf("customer reconcile state = %#v", updated.Reconciliation)
	}

	failedID, err := database.BeginReconcileRun(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.FinishReconcileRun(ctx, failedID, errors.New("GMP unavailable")); err != nil {
		t.Fatalf("FinishReconcileRun(failed) error = %v", err)
	}
	allRuns, err := database.ReconcileRuns(ctx, "", 101)
	if err != nil {
		t.Fatalf("ReconcileRuns(all) error = %v", err)
	}
	if len(allRuns) != 2 || allRuns[0].Status != "failed" {
		t.Errorf("all runs = %#v", allRuns)
	}
}

func TestStoreReconcileRunMissingRows(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	database := openTestStore(t)
	if err := database.UpdateReconcileProgress(ctx, 9999, "missing", ReconcileProgress{}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UpdateReconcileProgress() error = %v, want sql.ErrNoRows", err)
	}
	if err := database.FinishReconcileRun(ctx, 9999, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("FinishReconcileRun() error = %v, want sql.ErrNoRows", err)
	}
}

package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"openvasconf/internal/customer"
)

func TestReportRetentionKeepsThreePerTaskAndPreservesFindingState(t *testing.T) {
	repository := openTestStore(t)
	ctx := t.Context()
	// Seed the previous schema to verify that the upgrade preserves existing
	// annotations and changes the report foreign key without cascading state.
	legacy, err := migrationFiles.ReadFile("migrations/007_global_findings_hookwise.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(legacy)
	text = text[strings.Index(text, "CREATE TABLE finding_states ("):strings.Index(text, "INSERT INTO finding_states(")]
	if _, err := repository.db.ExecContext(ctx, "DROP TABLE finding_states; "+text+"DELETE FROM schema_migrations WHERE version = 11;"); err != nil {
		t.Fatal(err)
	}
	customer := testCustomer(t, "retention", []string{"10.1.0.1"})
	if err := repository.CreateCustomer(ctx, customer); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for _, task := range []string{"task-a", "task-b"} {
		for i := range 5 {
			snapshot := testSnapshot(customer.ID)
			snapshot.TaskID, snapshot.TaskName = task, task
			snapshot.ReportID = fmt.Sprintf("%s-%d", task, i)
			snapshot.ScanStart, snapshot.ScanEnd = base.Add(time.Duration(i)*time.Hour), base.Add(time.Duration(i+1)*time.Hour)
			findings := testFindings()
			if i > 0 {
				findings = findings[1:]
			}
			if err := repository.SaveReportSnapshot(ctx, snapshot, findings); err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				if err := repository.UpsertAnnotation(ctx, FindingAnnotation{CustomerID: customer.ID, TaskID: task, Fingerprint: "v1:aaa", Disposition: DispositionActive, RemediationState: RemediationWontFix, Justification: "accepted"}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if err := repository.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repository.PruneReportSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repository.PruneReportSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := repository.ListReportSnapshots(ctx, customer.ID, 100)
	if err != nil || len(rows) != 6 {
		t.Fatalf("retained reports = %d, %v; want 6", len(rows), err)
	}
	for _, row := range rows {
		if row.ScanEnd.Before(base.Add(3 * time.Hour)) {
			t.Fatalf("retained old report %s", row.ReportID)
		}
	}
	var snapshots, findings, states int
	for query, dest := range map[string]*int{"SELECT COUNT(*) FROM report_snapshots": &snapshots, "SELECT COUNT(*) FROM finding_snapshots": &findings, "SELECT COUNT(*) FROM finding_states": &states} {
		if err := repository.db.QueryRowContext(ctx, query).Scan(dest); err != nil {
			t.Fatal(err)
		}
	}
	if snapshots != 6 || findings != 6 || states != 4 {
		t.Fatalf("reports/findings/states = %d/%d/%d", snapshots, findings, states)
	}
	annotations, err := repository.AnnotationsForTask(ctx, customer.ID, "task-a")
	if err != nil || annotations["v1:aaa"].RemediationState != RemediationWontFix {
		t.Fatalf("lost task annotation: %#v, %v", annotations, err)
	}
	current, total, err := repository.CurrentFindings(ctx, FindingQuery{})
	if err != nil || len(current) != 2 || total != 2 {
		t.Fatalf("current findings = %d/%d, %v", len(current), total, err)
	}
	// A finding that returns after its old report expired keeps its first-seen
	// date and task-specific suppression.
	snapshot := testSnapshot(customer.ID)
	snapshot.TaskID, snapshot.TaskName, snapshot.ReportID = "task-a", "task-a", "returned"
	snapshot.ScanStart, snapshot.ScanEnd = base.Add(8*time.Hour), base.Add(9*time.Hour)
	if err := repository.SaveReportSnapshot(ctx, snapshot, testFindings()); err != nil {
		t.Fatal(err)
	}
	suppressed, total, err := repository.CurrentFindings(ctx, FindingQuery{Scope: FindingScopeSuppressed})
	if err != nil || total != 1 || !suppressed[0].FirstSeen.Equal(base.Add(time.Hour)) {
		t.Fatalf("returning finding state = %#v, %v", suppressed, err)
	}
}

func TestReportRetentionDoesNotLosePendingTicketClosure(t *testing.T) {
	repository := openTestStore(t)
	value := testCustomer(t, "retention-ticket", []string{"10.57.0.1"})
	value.ConnectWiseCustomerName = "Acme"
	if err := repository.CreateCustomer(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	fixture := customerFixture{customerID: value.ID, scanEnd: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	saveTicketSnapshot(t, repository, fixture, "original", fixture.scanEnd, 8.5)
	if err := repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher"}); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		snapshot := ReportSnapshot{ReportID: fmt.Sprintf("empty-%d", i), CustomerID: fixture.customerID, TaskID: "task-1", TaskName: "task", ScanStart: fixture.scanEnd.Add(time.Duration(i) * time.Hour), ScanEnd: fixture.scanEnd.Add(time.Duration(i+1) * time.Hour), Status: "Done"}
		if err := repository.SaveReportSnapshot(t.Context(), snapshot, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.PruneReportSnapshots(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	var closes int
	if err := repository.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM hookwise_outbox WHERE event_type = 'closed'").Scan(&closes); err != nil {
		t.Fatal(err)
	}
	if closes != 1 {
		t.Fatalf("close events after retention = %d, want 1", closes)
	}
	var openJSON, closeJSON []byte
	if err := repository.db.QueryRowContext(t.Context(), "SELECT payload FROM hookwise_outbox WHERE event_type='open'").Scan(&openJSON); err != nil {
		t.Fatal(err)
	}
	if err := repository.db.QueryRowContext(t.Context(), "SELECT payload FROM hookwise_outbox WHERE event_type='closed'").Scan(&closeJSON); err != nil {
		t.Fatal(err)
	}
	var opened, closed map[string]any
	if err := json.Unmarshal(openJSON, &opened); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(closeJSON, &closed); err != nil {
		t.Fatal(err)
	}
	if closed["summary"] != opened["summary"] || closed["host"] != opened["host"] || closed["title"] != opened["title"] || closed["report_path"] != "" {
		t.Fatalf("expired ticket context was lost: %#v", closed)
	}
}

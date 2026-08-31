package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"openvasconf/internal/customer"
	"openvasconf/internal/id"
	"openvasconf/internal/networkplan"
)

func TestStoreCustomerLifecycle(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	settings, err := store.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings() error = %v", err)
	}
	if settings.InstallationID == "" || settings.Timezone != "Europe/Vienna" {
		t.Fatalf("settings = %#v", settings)
	}

	value := testCustomer(t, "testcomp1", []string{"10.1.0.0/16", "7.7.7.7"})
	if err := store.CreateCustomer(ctx, value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	got, err := store.Customer(ctx, value.ID)
	if err != nil {
		t.Fatalf("Customer() error = %v", err)
	}
	if got.Name != value.Name || len(got.Networks) != 2 || got.DesiredRevision != 1 {
		t.Fatalf("customer = %#v", got)
	}
	originalWeekday := got.ScheduleWeekday
	originalMinute := got.ScheduleMinute

	got.Name = "testcomp1-renamed"
	got.SafeName = networkplan.SafeName(got.Name)
	got.Networks = got.Networks[:1]
	if err := store.UpdateCustomer(ctx, got); err != nil {
		t.Fatalf("UpdateCustomer() error = %v", err)
	}
	updated, err := store.Customer(ctx, value.ID)
	if err != nil {
		t.Fatalf("Customer(updated) error = %v", err)
	}
	if updated.DesiredRevision != 2 || len(updated.Networks) != 1 {
		t.Fatalf("updated customer = %#v", updated)
	}
	if updated.ScheduleWeekday != originalWeekday || updated.ScheduleMinute != originalMinute {
		t.Errorf(
			"schedule changed during customer update: weekday=%d minute=%d",
			updated.ScheduleWeekday,
			updated.ScheduleMinute,
		)
	}

	if err := store.SoftDeleteCustomer(ctx, value.ID); err != nil {
		t.Fatalf("SoftDeleteCustomer() error = %v", err)
	}
	active, err := store.Customers(ctx, false)
	if err != nil {
		t.Fatalf("Customers() error = %v", err)
	}
	if len(active) != 0 {
		t.Errorf("active customer count = %d, want 0", len(active))
	}
	deleted, err := store.Customer(ctx, value.ID)
	if err != nil {
		t.Fatalf("Customer(deleted) error = %v", err)
	}
	if deleted.DeletedAt == nil || deleted.DesiredRevision != 3 {
		t.Errorf("deleted customer = %#v", deleted)
	}
}

func TestStoreManagedResourceAndAudit(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := openTestStore(t)
	value := testCustomer(t, "managed", []string{"10.0.0.1"})
	if err := store.CreateCustomer(ctx, value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	resource := ManagedResource{
		CustomerID:      value.ID,
		Kind:            "target",
		Class:           "PrivateIP",
		Sequence:        1,
		GVMID:           "gvm-target-id",
		DesiredHash:     "hash",
		OwnershipMarker: "openvasconf:test",
		State:           "applied",
	}
	if err := store.UpsertManagedResource(ctx, resource); err != nil {
		t.Fatalf("UpsertManagedResource() error = %v", err)
	}
	resources, err := store.ManagedResources(ctx, value.ID)
	if err != nil {
		t.Fatalf("ManagedResources() error = %v", err)
	}
	if len(resources) != 1 || resources[0].GVMID != resource.GVMID {
		t.Fatalf("resources = %#v", resources)
	}

	if err := store.AddAuditEvent(ctx, AuditEvent{
		CustomerID:   value.ID,
		Action:       "created",
		ResourceKind: "target",
		ResourceName: "managed_PrivateIP_Target1",
	}); err != nil {
		t.Fatalf("AddAuditEvent() error = %v", err)
	}
	events, err := store.AuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("AuditEvents() error = %v", err)
	}
	if len(events) != 1 || events[0].Action != "created" {
		t.Fatalf("events = %#v", events)
	}

	if err := store.DeleteManagedResource(ctx, value.ID, "target", "PrivateIP", 1); err != nil {
		t.Fatalf("DeleteManagedResource() error = %v", err)
	}
	resources, err = store.ManagedResources(ctx, value.ID)
	if err != nil {
		t.Fatalf("ManagedResources(after delete) error = %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("resource count = %d, want 0", len(resources))
	}
}

func TestStorePersistsAcrossRestart(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "persist.db")
	first, err := Open(ctx, path, "Europe/Vienna")
	if err != nil {
		t.Fatalf("Open(first) error = %v", err)
	}
	settings, err := first.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings(first) error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}

	second, err := Open(ctx, path, "UTC")
	if err != nil {
		t.Fatalf("Open(second) error = %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	restarted, err := second.Settings(ctx)
	if err != nil {
		t.Fatalf("Settings(second) error = %v", err)
	}
	if restarted.InstallationID != settings.InstallationID || restarted.Timezone != "Europe/Vienna" {
		t.Errorf("restarted settings = %#v, initial = %#v", restarted, settings)
	}
}

func TestConnectWiseCustomerNameMigrationBackfillsCID(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "connectwise-name-upgrade.db")
	dsn := "file:" + url.PathEscape(filepath.ToSlash(path)) + "?_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	legacy := &Store{db: db}
	for _, migration := range []struct {
		version int
		name    string
	}{
		{version: 1, name: "001_initial.sql"},
		{version: 2, name: "002_operator_features.sql"},
		{version: 3, name: "003_schedule_freedom.sql"},
		{version: 4, name: "004_reporting.sql"},
		{version: 5, name: "005_lifecycle.sql"},
		{version: 6, name: "006_updater.sql"},
		{version: 7, name: "007_global_findings_hookwise.sql"},
	} {
		statement, readErr := migrationFiles.ReadFile("migrations/" + migration.name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err := legacy.applyMigration(ctx, migration.version, string(statement)); err != nil {
			t.Fatalf("applyMigration(%d) error = %v", migration.version, err)
		}
	}
	const storedTime = "2026-08-31T15:00:00Z"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO customers(
			id, name, safe_name, cid, schedule_weekday, schedule_minute,
			timezone, created_at, updated_at
		) VALUES('connectwise-name', 'Customer', 'customer', 'Acme Europe GmbH',
		         2, 540, 'Europe/Vienna', ?, ?)`, storedTime, storedTime); err != nil {
		t.Fatalf("seeding legacy customer: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO hookwise_outbox(
			event_key, customer_id, task_id, fingerprint, generation,
			event_type, payload, next_attempt_at, created_at
		) VALUES('legacy-event', 'connectwise-name', 'task', 'finding', 1,
		         'open', '{"cid":"Acme Europe GmbH","state":"open"}', ?, ?)`,
		storedTime,
		storedTime,
	); err != nil {
		t.Fatalf("seeding legacy Hookwise event: %v", err)
	}
	migration, err := migrationFiles.ReadFile("migrations/008_connectwise_customer_name.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.applyMigration(ctx, 8, string(migration)); err != nil {
		t.Fatalf("applyMigration(8) error = %v", err)
	}
	var connectWiseCustomerName, legacyCID string
	if err := db.QueryRowContext(ctx, `
		SELECT connectwise_customer_name, cid FROM customers WHERE id = ?`,
		"connectwise-name",
	).Scan(&connectWiseCustomerName, &legacyCID); err != nil {
		t.Fatal(err)
	}
	if connectWiseCustomerName != "Acme Europe GmbH" || legacyCID != connectWiseCustomerName {
		t.Errorf(
			"customer names after migration = %q, %q",
			connectWiseCustomerName,
			legacyCID,
		)
	}
	var payloadText string
	if err := db.QueryRowContext(
		ctx,
		"SELECT payload FROM hookwise_outbox WHERE event_key = 'legacy-event'",
	).Scan(&payloadText); err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payloadText), &payload); err != nil {
		t.Fatalf("decoding migrated Hookwise payload: %v", err)
	}
	var migratedName string
	if err := json.Unmarshal(payload["connectwise_customer_name"], &migratedName); err != nil {
		t.Fatalf("decoding migrated customer name: %v", err)
	}
	if migratedName != "Acme Europe GmbH" {
		t.Errorf("migrated customer name = %q", migratedName)
	}
	if _, found := payload["cid"]; found {
		t.Error("legacy cid remains in migrated Hookwise payload")
	}
	var version int
	if err := db.QueryRowContext(
		ctx,
		"SELECT version FROM schema_migrations WHERE version = 8",
	).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 8 {
		t.Errorf("migration version = %d, want 8", version)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGreenboneFindingDetailsMigrationPreservesLegacyRows(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "greenbone-details-upgrade.db")
	dsn := "file:" + url.PathEscape(filepath.ToSlash(path)) + "?_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	legacy := &Store{db: db}
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 8; version++ {
		var name string
		prefix := fmt.Sprintf("%03d_", version)
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), prefix) {
				name = entry.Name()
				break
			}
		}
		if name == "" {
			t.Fatalf("migration %d not found", version)
		}
		statement, readErr := migrationFiles.ReadFile("migrations/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err := legacy.applyMigration(ctx, version, string(statement)); err != nil {
			t.Fatalf("applyMigration(%d) error = %v", version, err)
		}
	}
	const storedTime = "2026-08-31T15:00:00.000000000Z"
	result, err := db.ExecContext(ctx, `
		INSERT INTO report_snapshots(
			report_id, task_id, task_name, import_state, created_at
		) VALUES('legacy-report', 'legacy-task', 'Legacy task', 'imported', ?)`, storedTime)
	if err != nil {
		t.Fatalf("seeding legacy report: %v", err)
	}
	snapshotID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO finding_snapshots(snapshot_id, fingerprint, title, cves, remediation)
		VALUES(?, 'v1:legacy', 'Legacy finding', 'CVE-2026-1234', 'Legacy fix')`, snapshotID); err != nil {
		t.Fatalf("seeding legacy finding: %v", err)
	}
	migration, err := migrationFiles.ReadFile("migrations/009_greenbone_finding_details.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.applyMigration(ctx, 9, string(migration)); err != nil {
		t.Fatalf("applyMigration(9) error = %v", err)
	}
	var title, evidence, cvssVector, summary, insight, impact, affected, solutionType, references string
	if err := db.QueryRowContext(ctx, `
		SELECT title, evidence, cvss_vector, summary, insight, impact, affected,
		       solution_type, nvt_references
		FROM finding_snapshots WHERE fingerprint = 'v1:legacy'`).Scan(
		&title, &evidence, &cvssVector, &summary, &insight, &impact, &affected,
		&solutionType, &references,
	); err != nil {
		t.Fatal(err)
	}
	if title != "Legacy finding" || evidence != "" || cvssVector != "" ||
		summary != "" || insight != "" || impact != "" || affected != "" ||
		solutionType != "" || references != "[]" {
		t.Errorf("migrated finding = %q %q %q %q %q %q %q %q %q",
			title, evidence, cvssVector, summary, insight, impact, affected, solutionType, references)
	}
	var version int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_migrations WHERE version = 9").Scan(&version); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleFreedomMigrationPreservesForeignKeyChildren(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "upgrade.db")
	dsn := "file:" + url.PathEscape(filepath.ToSlash(path)) + "?_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	legacy := &Store{db: db}
	for _, migration := range []struct {
		version int
		name    string
	}{
		{version: 1, name: "001_initial.sql"},
		{version: 2, name: "002_operator_features.sql"},
	} {
		statement, err := migrationFiles.ReadFile("migrations/" + migration.name)
		if err != nil {
			t.Fatal(err)
		}
		if err := legacy.applyMigration(ctx, migration.version, string(statement)); err != nil {
			t.Fatalf("applyMigration(%d) error = %v", migration.version, err)
		}
	}
	const storedTime = "2026-08-24T12:00:00Z"
	for _, statement := range []string{
		`INSERT INTO settings(singleton, installation_id, timezone, updated_at)
		 VALUES(1, 'install-upgrade', 'Europe/Vienna', '` + storedTime + `')`,
		`INSERT INTO customers(id, name, safe_name, schedule_weekday, schedule_minute,
		 timezone, created_at, updated_at)
		 VALUES('customer-upgrade', 'upgrade', 'upgrade', 1, 420,
		 'Europe/Vienna', '` + storedTime + `', '` + storedTime + `')`,
		`INSERT INTO networks(id, customer_id, input, prefix, class, created_at)
		 VALUES('network-upgrade', 'customer-upgrade', '10.0.0.1', '10.0.0.1/32',
		 'PrivateIP', '` + storedTime + `')`,
		`INSERT INTO managed_resources(customer_id, kind, class, sequence,
		 ownership_marker, updated_at)
		 VALUES('customer-upgrade', 'target', 'PrivateIP', 1,
		 'openvasconf:upgrade', '` + storedTime + `')`,
		`INSERT INTO reconcile_runs(customer_id, started_at, status, error)
		 VALUES('customer-upgrade', '` + storedTime + `', 'completed', '')`,
		`INSERT INTO audit_events(customer_id, action, created_at)
		 VALUES('customer-upgrade', 'created', '` + storedTime + `')`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("seeding legacy database: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, path, "UTC")
	if err != nil {
		t.Fatalf("Open(upgrade) error = %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	for _, table := range []string{"networks", "managed_resources", "reconcile_runs", "audit_events"} {
		var count int
		// #nosec G202 -- table comes from the fixed test allowlist above.
		query := "SELECT COUNT(*) FROM " + table + " WHERE customer_id = 'customer-upgrade'"
		if err := upgraded.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("%s rows after upgrade = %d, want 1", table, count)
		}
	}
	settings, err := upgraded.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.SLA != (customer.SLAPolicy{CriticalDays: 7, HighDays: 14, MediumDays: 30, LowDays: 90}) {
		t.Errorf("upgraded SLA defaults = %#v", settings.SLA)
	}
	var foreignKeysEnabled int
	if err := upgraded.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeysEnabled); err != nil {
		t.Fatal(err)
	}
	if foreignKeysEnabled != 1 {
		t.Errorf("foreign-key enforcement after upgrade = %d, want 1", foreignKeysEnabled)
	}
	rows, err := upgraded.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("closing foreign-key check rows: %v", err)
		}
	}()
	if rows.Next() {
		t.Fatal("foreign_key_check found a violation after upgrade")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "test.db"), "Europe/Vienna")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func testCustomer(t *testing.T, name string, inputs []string) customer.Customer {
	t.Helper()
	customerID, err := id.New()
	if err != nil {
		t.Fatalf("id.New() error = %v", err)
	}
	weekday, minute, err := customer.RandomSchedule(nil)
	if err != nil {
		t.Fatalf("RandomSchedule() error = %v", err)
	}
	value := customer.Customer{
		ID:              customerID,
		Name:            name,
		SafeName:        networkplan.SafeName(name),
		ScheduleWeekday: weekday,
		ScheduleMinute:  minute,
		Timezone:        "Europe/Vienna",
		Networks:        make([]customer.Network, 0, len(inputs)),
	}
	for _, input := range inputs {
		prefix, err := networkplan.Parse(input)
		if err != nil {
			t.Fatalf("networkplan.Parse(%q) error = %v", input, err)
		}
		plan, err := networkplan.Build(networkplan.Input{
			CustomerName: name,
			Networks:     []string{input},
		})
		if err != nil {
			t.Fatalf("networkplan.Build(%q) error = %v", input, err)
		}
		networkID, err := id.New()
		if err != nil {
			t.Fatalf("id.New() error = %v", err)
		}
		value.Networks = append(value.Networks, customer.Network{
			ID:         networkID,
			CustomerID: customerID,
			Input:      input,
			Prefix:     prefix.String(),
			Class:      string(plan.Targets[0].Class),
		})
	}
	return value
}

func TestStoreNotFound(t *testing.T) {
	t.Parallel()
	store := openTestStore(t)
	_, err := store.Customer(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Customer(missing) error = %v, want ErrNotFound", err)
	}
}

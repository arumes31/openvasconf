package store

import (
	"context"
	"errors"
	"path/filepath"
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

package store

import (
	"testing"

	"openvasconf/internal/customer"
	"openvasconf/internal/networkplan"
)

func TestStoreApplyImportCreatesAndUpdatesCustomers(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	database := openTestStore(t)
	settings, err := database.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	settings.Timezone = "UTC"
	settings.SchedulePolicy = customer.SchedulePolicy{Weekdays: []int{1, 3, 5}, StartMinute: 60, EndMinute: 120}
	value := testCustomer(t, "imported", []string{"10.40.0.0/24"})
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	value.Description = "created by import"
	value.Tags = []string{"imported", "production"}
	if err := database.ApplyImport(ctx, settings, []customer.Customer{value}); err != nil {
		t.Fatalf("ApplyImport(create) error = %v", err)
	}

	created, err := database.Customer(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if created.ConnectWiseCustomerName != value.ConnectWiseCustomerName ||
		len(created.Networks) != 1 || created.DesiredRevision != 1 {
		t.Errorf("created customer = %#v", created)
	}
	gotSettings, err := database.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gotSettings.Timezone != "UTC" || len(gotSettings.SchedulePolicy.Weekdays) != 3 {
		t.Errorf("settings after import = %#v", gotSettings)
	}

	value.Name = "imported-updated"
	value.SafeName = networkplan.SafeName(value.Name)
	value.Networks = testCustomer(t, "temporary", []string{"7.7.7.8"}).Networks
	for index := range value.Networks {
		value.Networks[index].CustomerID = value.ID
	}
	if err := database.ApplyImport(ctx, settings, []customer.Customer{value}); err != nil {
		t.Fatalf("ApplyImport(update) error = %v", err)
	}
	updated, err := database.Customer(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != value.Name || updated.Networks[0].Prefix != "7.7.7.8/32" || updated.DesiredRevision != 2 {
		t.Errorf("updated customer = %#v", updated)
	}
}

func TestStoreApplyImportRollsBackInvalidInput(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	database := openTestStore(t)
	settings, err := database.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	invalidPolicy := settings
	invalidPolicy.SchedulePolicy.Weekdays = nil
	if err := database.ApplyImport(ctx, invalidPolicy, nil); err == nil {
		t.Fatal("ApplyImport(invalid policy) error = nil")
	}

	settings.Timezone = "UTC"
	value := testCustomer(t, "invalid-import", []string{"6.6.6.0/24"})
	value.ConnectWiseCustomerName = " invalid customer name"
	if err := database.ApplyImport(ctx, settings, []customer.Customer{value}); err == nil {
		t.Fatal("ApplyImport(invalid ConnectWise customer name) error = nil")
	}
	if _, err := database.Customer(ctx, value.ID); err == nil {
		t.Fatal("invalid customer was committed")
	}
	gotSettings, err := database.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gotSettings.Timezone == "UTC" {
		t.Error("settings update was not rolled back")
	}
}

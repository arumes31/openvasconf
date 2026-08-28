package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"openvasconf/internal/customer"
)

func TestCustomerActionsLifecycle(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)
	value := seedActionCustomer(t, app)

	response := postForm(t, app, "/customers/"+value.ID+"/sync", nil)
	if body := readBody(t, response); response.StatusCode != http.StatusOK || !strings.Contains(body, "Customer reconciliation requested") {
		t.Fatalf("customer sync response = %d: %s", response.StatusCode, body)
	}
	response = postForm(t, app, "/sync-selected", nil)
	if body := readBody(t, response); response.StatusCode != http.StatusOK || !strings.Contains(body, "Select at least one customer") {
		t.Fatalf("empty bulk sync response = %d: %s", response.StatusCode, body)
	}
	response = postForm(t, app, "/sync-selected", url.Values{"customer_id": {value.ID}})
	_ = readBody(t, response)
	if app.syncer.count.Load() != 2 {
		t.Errorf("sync triggers = %d, want 2", app.syncer.count.Load())
	}

	response, err := app.client.Get(app.server.URL + "/customers/" + value.ID + "/history")
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, response); response.StatusCode != http.StatusOK || !strings.Contains(body, "Reconciliation history") {
		t.Fatalf("history response = %d: %s", response.StatusCode, body)
	}

	response = postForm(t, app, "/customers/"+value.ID+"/clone", nil)
	_ = readBody(t, response)
	values, err := app.repository.Customers(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 {
		t.Fatalf("customer count after clone = %d, want 2", len(values))
	}
	var clone customer.Customer
	for _, candidate := range values {
		if candidate.ID != value.ID {
			clone = candidate
		}
	}
	if clone.Name != value.Name+" copy" || clone.Networks[0].ID == value.Networks[0].ID {
		t.Errorf("clone = %#v", clone)
	}

	beforeRevision := clone.DesiredRevision
	response = postForm(t, app, "/customers/"+clone.ID+"/randomize", nil)
	_ = readBody(t, response)
	randomized, err := app.repository.Customer(t.Context(), clone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if randomized.DesiredRevision != beforeRevision+1 {
		t.Errorf("revision after randomize = %d, want %d", randomized.DesiredRevision, beforeRevision+1)
	}

	response, err = app.client.Get(app.server.URL + "/api/customers/" + value.ID + "/progress")
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, response); response.StatusCode != http.StatusOK || !strings.Contains(body, `"progress"`) {
		t.Fatalf("progress response = %d: %s", response.StatusCode, body)
	}
	response, err = app.client.Get(app.server.URL + "/api/customers/missing/progress")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("missing progress status = %d, want 404", response.StatusCode)
	}
}

func TestCustomerActionsRejectMissingCustomers(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)
	for _, path := range []string{
		"/customers/missing/sync",
		"/customers/missing/clone",
		"/customers/missing/randomize",
	} {
		response := postForm(t, app, path, nil)
		_ = readBody(t, response)
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s status = %d, want 404", path, response.StatusCode)
		}
	}
	response, err := app.client.Get(app.server.URL + "/customers/missing/history")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("missing history status = %d, want 404", response.StatusCode)
	}
}

func seedActionCustomer(t *testing.T, app testWebApp) customer.Customer {
	t.Helper()
	value := customer.Customer{
		ID: "customer-actions", Name: "actions", SafeName: "actions",
		ScheduleWeekday: 2, ScheduleMinute: 9 * 60, Timezone: "Europe/Vienna",
		Networks: []customer.Network{{
			ID: "customer-actions-network", CustomerID: "customer-actions", Input: "10.60.0.1",
			Prefix: "10.60.0.1/32", Class: "PrivateIP",
		}},
	}
	if err := app.repository.CreateCustomer(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	return value
}

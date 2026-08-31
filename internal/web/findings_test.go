package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"openvasconf/internal/customer"
	"openvasconf/internal/store"
)

type findingRetryManager struct {
	customerID  string
	taskID      string
	fingerprint string
	action      string
	err         error
}

func (*findingRetryManager) Trigger() {}

func (*findingRetryManager) Save(context.Context, bool, string, string) error { return nil }

func (*findingRetryManager) Test(context.Context) error { return nil }

func (*findingRetryManager) Retry(context.Context) error { return nil }

func (m *findingRetryManager) RetryFinding(
	_ context.Context,
	customerID,
	taskID,
	fingerprint string,
) error {
	m.customerID = customerID
	m.taskID = taskID
	m.fingerprint = fingerprint
	m.action = "retry"
	return m.err
}

func (m *findingRetryManager) RecreateFinding(
	_ context.Context,
	customerID,
	taskID,
	fingerprint string,
) error {
	m.customerID = customerID
	m.taskID = taskID
	m.fingerprint = fingerprint
	m.action = "recreate"
	return m.err
}

func (*findingRetryManager) Stats(context.Context) (store.HookwiseStats, error) {
	return store.HookwiseStats{}, nil
}

func (*findingRetryManager) Health(context.Context) (string, string, string, string) {
	return "ok", "ticket delivery current", "", "/findings"
}

func TestFindingsListAndPermanentSuppression(t *testing.T) {
	app := newReportTestApp(t)
	snapshot := seedReportSnapshot(t, app)
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/findings")
	if err != nil {
		t.Fatalf("GET /findings error = %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "OpenSSH Weak Encryption") {
		t.Fatalf("findings page status=%d body=%s", response.StatusCode, body)
	}
	if !strings.Contains(string(body), "https://nvd.nist.gov/vuln/detail/CVE-2021-1234") {
		t.Fatalf("findings page does not contain validated CVE link: %s", body)
	}

	response = postForm(t, app.testWebApp, "/findings/state", url.Values{
		"customer_id": {snapshot.CustomerID},
		"task_id":     {snapshot.TaskID},
		"fingerprint": {"v1:seeded"},
		"state":       {store.RemediationWontFix},
		"reason":      {"customer accepted the exposure"},
	})
	_ = response.Body.Close()

	active, err := app.client.Get(app.server.URL + "/findings")
	if err != nil {
		t.Fatalf("GET active findings error = %v", err)
	}
	activeBody, _ := io.ReadAll(active.Body)
	_ = active.Body.Close()
	if strings.Contains(string(activeBody), "OpenSSH Weak Encryption") {
		t.Errorf("suppressed finding remained in active view")
	}

	suppressed, err := app.client.Get(app.server.URL + "/findings?scope=suppressed")
	if err != nil {
		t.Fatalf("GET suppressed findings error = %v", err)
	}
	suppressedBody, _ := io.ReadAll(suppressed.Body)
	_ = suppressed.Body.Close()
	if !strings.Contains(string(suppressedBody), "OpenSSH Weak Encryption") ||
		!strings.Contains(string(suppressedBody), "customer accepted the exposure") {
		t.Errorf("suppressed view body=%s", suppressedBody)
	}
}

func TestFindingsJSONExportUsesCurrentFilters(t *testing.T) {
	app := newReportTestApp(t)
	seedReportSnapshot(t, app)

	response, err := app.client.Get(app.server.URL + "/findings/export.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.Request.URL.Path != "/login" {
		t.Fatalf("unauthenticated export landed on %q", response.Request.URL.Path)
	}

	login(t, app.testWebApp)
	response, err = app.client.Get(
		app.server.URL + "/findings/export.json?severity=critical&host=10.7.0.1&scope=active",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if disposition := response.Header.Get("Content-Disposition"); !strings.Contains(disposition, "current-findings-") {
		t.Fatalf("Content-Disposition = %q", disposition)
	}
	var payload currentFindingExport
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 1 || payload.Exported != 1 || payload.Truncated {
		t.Fatalf("export metadata = %#v", payload)
	}
	if payload.Filters["severity"] != "critical" || payload.Filters["host"] != "10.7.0.1" {
		t.Fatalf("filters = %#v", payload.Filters)
	}
	if len(payload.Findings) != 1 || payload.Findings[0].Fingerprint != "v1:seeded" ||
		len(payload.Findings[0].CVEs) != 1 {
		t.Fatalf("findings = %#v", payload.Findings)
	}
}

func TestScanFailureAlertRendersAndAcknowledges(t *testing.T) {
	app := newReportTestApp(t)
	snapshot := seedReportSnapshot(t, app)
	inserted, err := app.repository.RecordScanFailure(t.Context(), store.ScanAlert{
		CustomerID: snapshot.CustomerID,
		TaskID:     snapshot.TaskID, TaskName: snapshot.TaskName,
		ReportID: "failed-report-ui", Status: "Interrupted",
		Reason: "Greenbone scan ended with status \"Interrupted\"",
	})
	if err != nil || !inserted {
		t.Fatalf("RecordScanFailure() = %t, %v", inserted, err)
	}
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/findings")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "SCAN FAILED") || !strings.Contains(string(body), "Interrupted") {
		t.Fatalf("alert not rendered: %s", body)
	}
	alerts, err := app.repository.OpenScanAlerts(t.Context(), 20)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("alerts = %#v, %v", alerts, err)
	}
	response = postForm(
		t,
		app.testWebApp,
		"/scan-alerts/"+strconv.FormatInt(alerts[0].ID, 10)+"/acknowledge",
		nil,
	)
	bodyAfterAcknowledge := readBody(t, response)
	if strings.Contains(bodyAfterAcknowledge, "SCAN FAILED") {
		t.Fatalf("acknowledged alert still rendered: %s", bodyAfterAcknowledge)
	}
}

func TestFindingStateRequiresReason(t *testing.T) {
	app := newReportTestApp(t)
	snapshot := seedReportSnapshot(t, app)
	login(t, app.testWebApp)
	response := postForm(t, app.testWebApp, "/findings/state", url.Values{
		"customer_id": {snapshot.CustomerID},
		"task_id":     {snapshot.TaskID},
		"fingerprint": {"v1:seeded"},
		"state":       {store.RemediationResolved},
	})
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
}

func TestFindingsRetryFailedTicket(t *testing.T) {
	manager := &findingRetryManager{}
	app := newReportTestAppWithHookwise(t, manager)
	snapshot := seedReportSnapshot(t, app)
	value, err := app.repository.Customer(t.Context(), snapshot.CustomerID)
	if err != nil {
		t.Fatalf("Customer() error = %v", err)
	}
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	if err := app.repository.UpdateCustomer(t.Context(), value); err != nil {
		t.Fatalf("UpdateCustomer() error = %v", err)
	}
	if err := app.repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{
		Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher",
	}); err != nil {
		t.Fatalf("UpdateHookwiseSettings() error = %v", err)
	}
	if err := app.repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("ReconcileHookwiseOutbox() error = %v", err)
	}
	events, err := app.repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
	}
	if err := app.repository.MarkHookwiseFailed(
		t.Context(), events[0], http.StatusServiceUnavailable, "upstream unavailable",
	); err != nil {
		t.Fatalf("MarkHookwiseFailed() error = %v", err)
	}
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/findings?ticket=failed")
	if err != nil {
		t.Fatalf("GET /findings error = %v", err)
	}
	body := readBody(t, response)
	if !strings.Contains(body, `action="/findings/ticket/retry"`) ||
		!strings.Contains(body, `aria-label="Retry ticket for OpenSSH Weak Encryption"`) ||
		!strings.Contains(body, ">Retry ticket</button>") {
		t.Fatalf("failed finding retry action not rendered: %s", body)
	}

	response = postForm(t, app.testWebApp, "/findings/ticket/retry", url.Values{
		"customer_id": {snapshot.CustomerID},
		"task_id":     {snapshot.TaskID},
		"fingerprint": {"v1:seeded"},
	})
	body = readBody(t, response)
	if response.Request.URL.Query().Get("notice") != "ticket-retry-requested" {
		t.Fatalf("retry redirect = %q", response.Request.URL.String())
	}
	if !strings.Contains(body, "Ticket delivery retry queued") {
		t.Fatalf("retry notice not rendered: %s", body)
	}
	if manager.customerID != snapshot.CustomerID || manager.taskID != snapshot.TaskID ||
		manager.fingerprint != "v1:seeded" || manager.action != "retry" {
		t.Fatalf("RetryFinding() identity = %q, %q, %q", manager.customerID, manager.taskID, manager.fingerprint)
	}
}

func TestFindingsForceRecreateOpenTicket(t *testing.T) {
	manager := &findingRetryManager{}
	app := newReportTestAppWithHookwise(t, manager)
	snapshot := seedReportSnapshot(t, app)
	value, err := app.repository.Customer(t.Context(), snapshot.CustomerID)
	if err != nil {
		t.Fatalf("Customer() error = %v", err)
	}
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	if err := app.repository.UpdateCustomer(t.Context(), value); err != nil {
		t.Fatalf("UpdateCustomer() error = %v", err)
	}
	if err := app.repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{
		Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher",
	}); err != nil {
		t.Fatalf("UpdateHookwiseSettings() error = %v", err)
	}
	if err := app.repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("ReconcileHookwiseOutbox() error = %v", err)
	}
	events, err := app.repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
	}
	if err := app.repository.MarkHookwiseDelivered(t.Context(), events[0], http.StatusAccepted); err != nil {
		t.Fatalf("MarkHookwiseDelivered() error = %v", err)
	}
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/findings?ticket=open")
	if err != nil {
		t.Fatalf("GET /findings error = %v", err)
	}
	body := readBody(t, response)
	if !strings.Contains(body, `action="/findings/ticket/recreate"`) ||
		!strings.Contains(body, `aria-label="Force recreate ticket for OpenSSH Weak Encryption"`) ||
		!strings.Contains(body, `data-confirm="Force Hookwise to create a new ticket attempt?`) ||
		!strings.Contains(body, ">Force recreate ticket</button>") {
		t.Fatalf("open finding recreate action not rendered: %s", body)
	}

	response = postForm(t, app.testWebApp, "/findings/ticket/recreate", url.Values{
		"customer_id": {snapshot.CustomerID},
		"task_id":     {snapshot.TaskID},
		"fingerprint": {"v1:seeded"},
	})
	body = readBody(t, response)
	if response.Request.URL.Query().Get("notice") != "ticket-recreate-requested" {
		t.Fatalf("recreate redirect = %q", response.Request.URL.String())
	}
	if !strings.Contains(body, "Fresh ticket creation queued") {
		t.Fatalf("recreate notice not rendered: %s", body)
	}
	if manager.customerID != snapshot.CustomerID || manager.taskID != snapshot.TaskID ||
		manager.fingerprint != "v1:seeded" || manager.action != "recreate" {
		t.Fatalf(
			"RecreateFinding() identity = %q, %q, %q, action %q",
			manager.customerID,
			manager.taskID,
			manager.fingerprint,
			manager.action,
		)
	}

	manager.err = store.ErrNotFound
	response = postForm(t, app.testWebApp, "/findings/ticket/recreate", url.Values{
		"customer_id": {snapshot.CustomerID},
		"task_id":     {snapshot.TaskID},
		"fingerprint": {"v1:seeded"},
	})
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("non-open recreate status = %d, want %d", response.StatusCode, http.StatusConflict)
	}
	_ = response.Body.Close()
}

package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"openvasconf/internal/store"
)

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

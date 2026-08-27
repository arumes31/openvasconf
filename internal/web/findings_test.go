package web

import (
	"io"
	"net/http"
	"net/url"
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

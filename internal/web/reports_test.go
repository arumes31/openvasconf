package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openvasconf/internal/auth"
	"openvasconf/internal/customer"
	"openvasconf/internal/store"
)

type fakeReportSync struct {
	triggers atomic.Int32
}

func (f *fakeReportSync) ReportHealth(context.Context) (state, detail, guidance, link string) {
	return "ok", "reports up to date", "", "/reports"
}

func (f *fakeReportSync) Trigger() {
	f.triggers.Add(1)
}

type reportTestApp struct {
	testWebApp
	reportSync *fakeReportSync
}

func newReportTestApp(t *testing.T) reportTestApp {
	t.Helper()
	repository, err := store.Open(
		context.Background(),
		filepath.Join(t.TempDir(), "openvasconf.db"),
		"Europe/Vienna",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })

	authenticator := auth.New(repository, time.Hour)
	if err := authenticator.Bootstrap(context.Background(), testAdminPassword); err != nil {
		t.Fatal(err)
	}
	reportSync := &fakeReportSync{}
	application, err := New(Options{
		Repository: repository,
		Auth:       authenticator,
		Greenbone:  fakeGreenbone{options: testOptions()},
		Syncer:     &triggerCounter{},
		Reports:    reportSync,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return reportTestApp{
		testWebApp: testWebApp{
			server:     server,
			client:     &http.Client{Jar: jar},
			repository: repository,
		},
		reportSync: reportSync,
	}
}

func seedReportSnapshot(t *testing.T, app reportTestApp) store.ReportSnapshot {
	t.Helper()
	ctx := context.Background()
	value := customer.Customer{
		ID:              "customer-reports",
		Name:            "reportcustomer",
		SafeName:        "reportcustomer",
		ScheduleWeekday: 3,
		ScheduleMinute:  480,
		Timezone:        "Europe/Vienna",
		Networks: []customer.Network{{
			ID:         "network-reports",
			CustomerID: "customer-reports",
			Input:      "10.7.0.1",
			Prefix:     "10.7.0.1/32",
			Class:      "PrivateIP",
		}},
	}
	if err := app.repository.CreateCustomer(ctx, value); err != nil {
		t.Fatal(err)
	}
	snapshot := store.ReportSnapshot{
		ReportID:    "report-uuid-seeded",
		TaskID:      "task-uuid-seeded",
		TaskName:    "reportcustomer_PrivateIP_Task1",
		CustomerID:  value.ID,
		ScanStart:   time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC),
		ScanEnd:     time.Date(2026, 8, 22, 2, 45, 0, 0, time.UTC),
		Status:      "Done",
		SeverityMax: 9.8,
		CountHigh:   1,
	}
	findings := []store.FindingSnapshot{{
		Fingerprint: "v1:seeded",
		NVTOID:      "1.3.6.1.4.1.25623.1.0.100001",
		Title:       "OpenSSH Weak Encryption",
		Host:        "10.7.0.1",
		Port:        "22/tcp",
		Severity:    9.8,
		Threat:      "High",
		QOD:         80,
		CVEs:        []string{"CVE-2021-1234"},
		Remediation: "Update OpenSSH",
	}}
	if err := app.repository.SaveReportSnapshot(ctx, snapshot, findings); err != nil {
		t.Fatal(err)
	}
	listed, err := app.repository.ListReportSnapshots(ctx, value.ID, 1)
	if err != nil || len(listed) != 1 {
		t.Fatalf("seeded snapshot lookup = %#v, %v", listed, err)
	}
	return listed[0]
}

func TestReportsListRequiresAuth(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	response, err := app.client.Get(app.server.URL + "/reports")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("closing response body: %v", err)
		}
	}()
	if response.Request.URL.Path != "/login" {
		t.Fatalf("unauthenticated /reports landed on %q, want /login", response.Request.URL.Path)
	}
}

func TestReportDetailUnknownID(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	login(t, app.testWebApp)
	response, err := app.client.Get(app.server.URL + "/reports/424242")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown report status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
}

func TestReportsRefreshRequiresCSRF(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	login(t, app.testWebApp)

	response, err := app.client.Post(app.server.URL+"/reports/refresh", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("refresh without csrf status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	if app.reportSync.triggers.Load() != 0 {
		t.Fatal("refresh without csrf triggered the syncer")
	}

	response = postForm(t, app.testWebApp, "/reports/refresh", nil)
	_ = readBody(t, response)
	if app.reportSync.triggers.Load() != 1 {
		t.Fatalf("trigger count = %d, want 1", app.reportSync.triggers.Load())
	}
}

func TestReportsListRendersSeededSnapshots(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	mapped := seedReportSnapshot(t, app)
	if err := app.repository.SaveReportSnapshot(t.Context(), store.ReportSnapshot{
		ReportID: "report-unmapped",
		TaskID:   "task-unmapped",
		TaskName: "Unmapped task",
		ScanEnd:  time.Date(2026, 8, 23, 2, 45, 0, 0, time.UTC),
		Status:   "Done",
	}, nil); err != nil {
		t.Fatal(err)
	}
	unmapped, err := app.repository.ListReportSnapshots(t.Context(), "", 10)
	if err != nil || len(unmapped) != 2 {
		t.Fatalf("report snapshots = %#v, %v", unmapped, err)
	}
	var unmappedID int64
	for _, snapshot := range unmapped {
		if snapshot.CustomerID == "" {
			unmappedID = snapshot.ID
		}
	}
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/reports")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reports status = %d", response.StatusCode)
	}
	for _, expected := range []string{
		"reportcustomer",
		"reportcustomer_PrivateIP_Task1",
		"report-uuid-seeded",
		"imported",
		"Report sync",
		"reports up to date",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("reports page misses %q", expected)
		}
	}
	if !strings.Contains(body, "/reports/compare?b="+itoa(mapped.ID)) {
		t.Error("mapped report is missing its Compare action")
	}
	if strings.Contains(body, "/reports/compare?b="+itoa(unmappedID)) {
		t.Error("unmapped report unexpectedly renders a Compare action")
	}
	if !strings.Contains(body, "/reports/"+itoa(unmappedID)) {
		t.Error("unmapped report is missing its Inspect action")
	}
}

func TestReportDetailRendersFindings(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	snapshot := seedReportSnapshot(t, app)
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/reports/" + itoa(snapshot.ID))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("report detail status = %d", response.StatusCode)
	}
	for _, expected := range []string{
		"OpenSSH Weak Encryption",
		"CVE-2021-1234",
		"Update OpenSSH",
		"10.7.0.1",
		"reportcustomer",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("report detail misses %q", expected)
		}
	}

	filtered, err := app.client.Get(app.server.URL + "/reports/" + itoa(snapshot.ID) + "?severity=low")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, filtered)
	if strings.Contains(body, "OpenSSH Weak Encryption") {
		t.Errorf("severity filter did not exclude the high finding")
	}
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}

func seedReportPair(t *testing.T, app reportTestApp) (store.ReportSnapshot, store.ReportSnapshot) {
	t.Helper()
	ctx := context.Background()
	value := customer.Customer{
		ID:              "customer-compare",
		Name:            "comparecust",
		SafeName:        "comparecust",
		ScheduleWeekday: 3,
		ScheduleMinute:  480,
		Timezone:        "Europe/Vienna",
		Networks: []customer.Network{{
			ID:         "network-compare",
			CustomerID: "customer-compare",
			Input:      "10.8.0.1",
			Prefix:     "10.8.0.1/32",
			Class:      "PrivateIP",
		}},
	}
	if err := app.repository.CreateCustomer(ctx, value); err != nil {
		t.Fatal(err)
	}
	finding := func(fingerprint, title string, severity float64) store.FindingSnapshot {
		return store.FindingSnapshot{
			Fingerprint: fingerprint,
			NVTOID:      "1.3.6.1.4.1.25623.1.0.1",
			Title:       title,
			Host:        "10.8.0.1",
			Port:        "22/tcp",
			Severity:    severity,
			Threat:      "High",
			QOD:         80,
		}
	}
	now := time.Now()
	seed := func(reportID string, scanEnd time.Time, findings []store.FindingSnapshot) store.ReportSnapshot {
		snapshot := store.ReportSnapshot{
			ReportID:     reportID,
			TaskID:       "task-compare",
			TaskName:     "comparecust_PrivateIP_Task1",
			CustomerID:   value.ID,
			ScanStart:    scanEnd.Add(-time.Hour),
			ScanEnd:      scanEnd,
			Status:       "Done",
			SeverityMax:  9.8,
			CountHigh:    len(findings),
			FindingCount: len(findings),
		}
		if err := app.repository.SaveReportSnapshot(ctx, snapshot, findings); err != nil {
			t.Fatal(err)
		}
		listed, err := app.repository.ListReportSnapshots(ctx, value.ID, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, stored := range listed {
			if stored.ReportID == reportID {
				return stored
			}
		}
		t.Fatalf("seeded snapshot %q not found", reportID)
		return store.ReportSnapshot{}
	}
	before := seed("report-before", now.Add(-14*24*time.Hour), []store.FindingSnapshot{
		finding("v1:keep", "Recurring Weakness", 9.8),
		finding("v1:gone", "Resolved Issue", 5.0),
	})
	after := seed("report-after", now.Add(-6*24*time.Hour), []store.FindingSnapshot{
		finding("v1:keep", "Recurring Weakness", 9.8),
		finding("v1:new", "Brand New Hole", 9.8),
	})
	return before, after
}

func TestReportDetailLifecycleAndSLA(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	_, after := seedReportPair(t, app)
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/reports/" + itoa(after.ID))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("detail status = %d", response.StatusCode)
	}
	for _, expected := range []string{
		"badge-new",
		"badge-recurring",
		"badge-overdue",
		"badge-due_soon",
		"Compare with previous",
		"SEVERITY TREND",
		"Brand New Hole",
		"Recurring Weakness",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("detail misses %q", expected)
		}
	}
}

func TestReportAnnotateCreateUpdateAndValidation(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	_, after := seedReportPair(t, app)
	login(t, app.testWebApp)
	ctx := context.Background()

	// Missing justification is rejected and re-renders the detail page.
	form := mapValues(map[string]string{
		"fingerprint":       "v1:new",
		"disposition":       "false_positive",
		"remediation_state": "open",
	})
	response := postForm(t, app.testWebApp, "/reports/"+itoa(after.ID)+"/findings/annotate", form)
	body := readBody(t, response)
	if !strings.Contains(body, "justification is required") {
		t.Fatalf("expected justification error, got:\n%.500s", body)
	}

	// Foreign fingerprints are rejected.
	form = mapValues(map[string]string{
		"fingerprint":       "v1:bogus",
		"disposition":       "active",
		"remediation_state": "open",
	})
	response = postForm(t, app.testWebApp, "/reports/"+itoa(after.ID)+"/findings/annotate", form)
	body = readBody(t, response)
	if !strings.Contains(body, "does not belong") {
		t.Fatalf("expected fingerprint error, got:\n%.500s", body)
	}

	// Valid annotation persists and renders.
	form = mapValues(map[string]string{
		"fingerprint":       "v1:new",
		"disposition":       "accepted_risk",
		"justification":     "accepted by security team",
		"remediation_state": "in_progress",
		"remediation_owner": "ops-team",
		"due_date":          "2026-09-01",
		"expires_at":        "2099-12-31",
	})
	response = postForm(t, app.testWebApp, "/reports/"+itoa(after.ID)+"/findings/annotate", form)
	_ = readBody(t, response)
	annotation, err := app.repository.Annotation(ctx, "customer-compare", "v1:new")
	if err != nil {
		t.Fatalf("Annotation() error = %v", err)
	}
	if annotation.Disposition != "accepted_risk" || annotation.RemediationOwner != "ops-team" ||
		annotation.DueDate == nil || annotation.ExpiresAt == nil {
		t.Fatalf("annotation = %#v", annotation)
	}

	response, err = app.client.Get(app.server.URL + "/reports/" + itoa(after.ID))
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, response)
	for _, expected := range []string{"badge-accepted_risk", "ops-team", "in_progress"} {
		if !strings.Contains(body, expected) {
			t.Errorf("annotated detail misses %q", expected)
		}
	}

	// The disposition filter keeps only the annotated finding.
	response, err = app.client.Get(app.server.URL + "/reports/" + itoa(after.ID) + "?disposition=accepted_risk")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, response)
	if !strings.Contains(body, "Brand New Hole") || strings.Contains(body, "Recurring Weakness") {
		t.Errorf("disposition filter did not isolate the annotated finding")
	}

	// Updating back to active clears the badge.
	form = mapValues(map[string]string{
		"fingerprint":       "v1:new",
		"disposition":       "active",
		"remediation_state": "resolved",
		"remediation_owner": "ops-team",
	})
	response = postForm(t, app.testWebApp, "/reports/"+itoa(after.ID)+"/findings/annotate", form)
	_ = readBody(t, response)
	annotation, err = app.repository.Annotation(ctx, "customer-compare", "v1:new")
	if err != nil {
		t.Fatalf("Annotation(updated) error = %v", err)
	}
	if annotation.Disposition != "active" || annotation.RemediationState != "resolved" {
		t.Errorf("updated annotation = %#v", annotation)
	}
}

func TestExpiredAnnotationRendersActive(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	_, after := seedReportPair(t, app)
	login(t, app.testWebApp)

	expired := time.Now().Add(-24 * time.Hour)
	if err := app.repository.UpsertAnnotation(context.Background(), store.FindingAnnotation{
		CustomerID:       "customer-compare",
		Fingerprint:      "v1:keep",
		Disposition:      "accepted_risk",
		Justification:    "temporary acceptance",
		RemediationState: "open",
		ExpiresAt:        &expired,
	}); err != nil {
		t.Fatal(err)
	}

	response, err := app.client.Get(app.server.URL + "/reports/" + itoa(after.ID))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if strings.Contains(body, "badge-accepted_risk") {
		t.Errorf("expired risk acceptance still renders as accepted_risk")
	}
	if !strings.Contains(body, "badge-active") {
		t.Errorf("expired risk acceptance does not render as active")
	}
}

func TestReportCompareClassificationAndOwnership(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	before, after := seedReportPair(t, app)
	other := seedReportSnapshot(t, app)
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/reports/compare?a=" + itoa(before.ID) + "&b=" + itoa(after.ID))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("compare status = %d", response.StatusCode)
	}
	for _, expected := range []string{
		"1 new findings",
		"1 recurring findings",
		"1 resolved findings",
		"Brand New Hole",
		"Resolved Issue",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("compare page misses %q", expected)
		}
	}

	// Cross-customer comparison is forbidden.
	response, err = app.client.Get(app.server.URL + "/reports/compare?a=" + itoa(other.ID) + "&b=" + itoa(after.ID))
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Errorf("cross-customer compare status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}

	// Unknown snapshots 404.
	response, err = app.client.Get(app.server.URL + "/reports/compare?a=999999&b=999998")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("unknown compare status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}

	// Defaulting "a" to the previous snapshot renders the same classification.
	response, err = app.client.Get(app.server.URL + "/reports/compare?b=" + itoa(after.ID))
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, response)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "1 new findings") {
		t.Errorf("compare with default previous = %d", response.StatusCode)
	}
}

func TestSettingsSLAPersist(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	login(t, app.testWebApp)

	form := mapValues(map[string]string{
		"scanner_id":        "scanner-1",
		"scan_config_id":    "config-1",
		"port_list_id":      "ports-1",
		"timezone":          "Europe/Vienna",
		"schedule_start":    "07:00",
		"schedule_end":      "15:00",
		"sla_critical_days": "3",
		"sla_high_days":     "10",
		"sla_medium_days":   "20",
		"sla_low_days":      "40",
	})
	form["schedule_weekday"] = []string{"1", "2"}
	response := postForm(t, app.testWebApp, "/settings", form)
	_ = readBody(t, response)

	settings, err := app.repository.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if settings.SLA.CriticalDays != 3 || settings.SLA.HighDays != 10 ||
		settings.SLA.MediumDays != 20 || settings.SLA.LowDays != 40 {
		t.Fatalf("persisted SLA = %#v", settings.SLA)
	}

	response, err = app.client.Get(app.server.URL + "/settings")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if !strings.Contains(body, `name="sla_critical_days"`) || !strings.Contains(body, `value="40"`) {
		t.Errorf("settings page does not render the SLA inputs")
	}

	// Negative values are rejected with an error page.
	form["sla_low_days"] = []string{"-5"}
	response = postForm(t, app.testWebApp, "/settings", form)
	body = readBody(t, response)
	if !strings.Contains(body, "SLA durations must be non-negative") {
		t.Errorf("negative SLA not rejected")
	}

	form["sla_low_days"] = []string{"3651"}
	response = postForm(t, app.testWebApp, "/settings", form)
	body = readBody(t, response)
	if !strings.Contains(body, "SLA durations must not exceed 3650 days") {
		t.Errorf("excessive SLA not rejected")
	}
}

func mapValues(values map[string]string) map[string][]string {
	result := make(map[string][]string, len(values))
	for key, value := range values {
		result[key] = []string{value}
	}
	return result
}

func TestReportExportRequiresAuth(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	_, after := seedReportPair(t, app)
	response, err := app.client.Get(app.server.URL + "/reports/" + itoa(after.ID) + "/export?format=csv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("closing response body: %v", err)
		}
	}()
	if response.Request.URL.Path != "/login" {
		t.Fatalf("unauthenticated export landed on %q, want /login", response.Request.URL.Path)
	}
}

func TestReportExportUnknownSnapshot(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	login(t, app.testWebApp)
	response, err := app.client.Get(app.server.URL + "/reports/987654/export?format=csv")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown export status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
}

func TestReportExportCSVHonorsFilters(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	_, after := seedReportPair(t, app)
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/reports/" + itoa(after.ID) + "/export?format=csv&severity=high")
	if err != nil {
		t.Fatal(err)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/csv") {
		t.Errorf("content type = %q", contentType)
	}
	if disposition := response.Header.Get("Content-Disposition"); !strings.Contains(disposition, "comparecust") ||
		!strings.Contains(disposition, "report-after") {
		t.Errorf("content disposition = %q", disposition)
	}
	body := readBody(t, response)
	for _, expected := range []string{"fingerprint,nvt_oid,title", "Brand New Hole", "Recurring Weakness", "v1:keep"} {
		if !strings.Contains(body, expected) {
			t.Errorf("csv export misses %q", expected)
		}
	}

	response, err = app.client.Get(app.server.URL + "/reports/" + itoa(after.ID) + "/export?format=csv&severity=low")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, response)
	if strings.Contains(body, "Brand New Hole") {
		t.Errorf("severity filter not honored in csv export")
	}
}

func TestReportExportSARIF(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	_, after := seedReportPair(t, app)
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/reports/" + itoa(after.ID) + "/export?format=sarif")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	for _, expected := range []string{`"version":"2.1.0"`, "openvasconf/v1", "v1:keep", "v1:new", "partialFingerprints"} {
		if !strings.Contains(body, expected) {
			t.Errorf("sarif export misses %q", expected)
		}
	}
}

func TestReportExportPDF(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	_, after := seedReportPair(t, app)
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/reports/" + itoa(after.ID) + "/export?format=pdf")
	if err != nil {
		t.Fatal(err)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "application/pdf" {
		t.Errorf("content type = %q", contentType)
	}
	body := readBody(t, response)
	if !strings.HasPrefix(body, "%PDF-") || !strings.Contains(body, "%%EOF") {
		t.Errorf("pdf export has invalid framing")
	}
	if !strings.Contains(body, "Brand New Hole") {
		t.Errorf("pdf export misses finding title")
	}
}

func TestReportExportRejectsUnknownFormat(t *testing.T) {
	t.Parallel()

	app := newReportTestApp(t)
	_, after := seedReportPair(t, app)
	login(t, app.testWebApp)

	response, err := app.client.Get(app.server.URL + "/reports/" + itoa(after.ID) + "/export?format=xlsx")
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, response)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown format status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
}

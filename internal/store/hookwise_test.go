package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"openvasconf/internal/customer"
)

func TestReconcileHookwiseOutboxIncludesGreenboneFindingDetails(t *testing.T) {
	repository := openTestStore(t)
	value := testCustomer(t, "greenbone-details", []string{"10.60.0.1"})
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	if err := repository.CreateCustomer(t.Context(), value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	scanEnd := time.Date(2026, 8, 31, 15, 30, 0, 0, time.UTC)
	snapshot := ReportSnapshot{
		ReportID: "greenbone-report-1", TaskID: "task-1", TaskName: "Private scan",
		CustomerID: value.ID, ScanStart: scanEnd.Add(-time.Hour), ScanEnd: scanEnd,
		Status: "Done",
	}
	finding := FindingSnapshot{
		Fingerprint: "v1:greenbone", NVTOID: "1.3.6.1.4.1.25623.1.0.100001",
		Title: "OpenSSH Weak Encryption", Host: "10.60.0.5", Port: "22/tcp",
		Location: "SSH service", Severity: 9.8, Threat: "High", QOD: 80,
		CVEs:        []string{"CVE-2021-1234", "CVE-2024-9999"},
		Remediation: "Install the vendor-fixed OpenSSH release.",
		Evidence:    "The remote SSH banner advertises legacy encryption algorithms.",
		CVSSVector:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		Summary:     "Weak SSH encryption algorithms are enabled.",
		Insight:     "The scanner negotiated a legacy cipher.",
		Impact:      "An attacker may weaken transport confidentiality.",
		Affected:    "OpenSSH before the fixed release.", SolutionType: "VendorFix",
		References: []string{"url: https://greenbone.example/nvt"},
	}
	if err := repository.SaveReportSnapshot(t.Context(), snapshot, []FindingSnapshot{finding}); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}
	if err := repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{
		Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher",
	}); err != nil {
		t.Fatalf("UpdateHookwiseSettings() error = %v", err)
	}
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("ReconcileHookwiseOutbox() error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
	}
	var payload struct {
		Description       string   `json:"description"`
		NVTOID            string   `json:"nvt_oid"`
		Threat            string   `json:"threat"`
		QOD               int      `json:"qod"`
		Location          string   `json:"location"`
		CVSSVector        string   `json:"cvss_vector"`
		NVTSummary        string   `json:"nvt_summary"`
		Evidence          string   `json:"evidence"`
		Insight           string   `json:"insight"`
		Impact            string   `json:"impact"`
		Affected          string   `json:"affected"`
		SolutionType      string   `json:"solution_type"`
		References        []string `json:"references"`
		GreenboneReportID string   `json:"greenbone_report_id"`
		ScanEnd           string   `json:"scan_end"`
	}
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for _, expected := range []string{
		"Risk details", "CVSS score: 9.8", "CVSS vector: AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"Quality of detection: 80%", "CVEs: CVE-2021-1234, CVE-2024-9999",
		"Evidence", finding.Evidence, "Technical insight", finding.Insight,
		"Impact", finding.Impact, "Affected", finding.Affected,
		"Remediation", finding.Remediation, "Greenbone context", finding.NVTOID,
	} {
		if !strings.Contains(payload.Description, expected) {
			t.Errorf("description missing %q:\n%s", expected, payload.Description)
		}
	}
	if payload.NVTOID != finding.NVTOID || payload.Threat != finding.Threat ||
		payload.QOD != finding.QOD || payload.Location != finding.Location ||
		payload.CVSSVector != finding.CVSSVector || payload.NVTSummary != finding.Summary ||
		payload.Evidence != finding.Evidence || payload.Insight != finding.Insight ||
		payload.Impact != finding.Impact || payload.Affected != finding.Affected ||
		payload.SolutionType != finding.SolutionType || len(payload.References) != 1 ||
		payload.GreenboneReportID != snapshot.ReportID || payload.ScanEnd == "" {
		t.Errorf("structured Greenbone payload = %#v", payload)
	}
}

func TestHookwiseDescriptionBoundsVerboseGreenboneSections(t *testing.T) {
	verbose := strings.Repeat("Greenbone detail ", 2000)
	description := hookwiseDescription(ticketCandidate{
		Title: "Verbose finding", CustomerName: "Customer", TaskName: "Task",
		Host: "10.60.0.5", Port: "22/tcp", Severity: 9.8,
		NVTOID: "1.3.6.1.4.1.25623.1.0.100001", GreenboneReportID: "report-1",
		Remediation: verbose + " required remediation", NVTSummary: verbose,
		Evidence: verbose, Insight: verbose, Impact: verbose, Affected: verbose,
		References: []string{verbose},
	})
	if length := len([]rune(description)); length > maxHookwiseDescriptionLength {
		t.Fatalf("description length = %d, want <= %d", length, maxHookwiseDescriptionLength)
	}
	for _, expected := range []string{
		"Risk details", "Remediation", "Greenbone context", "NVT OID:", "Report ID:",
	} {
		if !strings.Contains(description, expected) {
			t.Errorf("bounded description missing %q", expected)
		}
	}
}

func TestHookwiseSummaryIsReadableAndStableAcrossTitleChanges(t *testing.T) {
	repository := openTestStore(t)
	value := testCustomer(t, "stable-summary", []string{"10.61.0.1"})
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	if err := repository.CreateCustomer(t.Context(), value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	firstEnd := time.Date(2026, 8, 31, 16, 0, 0, 0, time.UTC)
	firstSnapshot := ReportSnapshot{
		ReportID: "summary-report-1", TaskID: "task-1", TaskName: "Private scan",
		CustomerID: value.ID, ScanEnd: firstEnd, Status: "Done",
	}
	finding := FindingSnapshot{
		Fingerprint: "v1:stable-summary", Title: "OpenSSH Weak Encryption",
		Host: "10.61.0.5", Port: "22/tcp", Severity: 9.0, Threat: "High",
	}
	if err := repository.SaveReportSnapshot(t.Context(), firstSnapshot, []FindingSnapshot{finding}); err != nil {
		t.Fatalf("SaveReportSnapshot(first) error = %v", err)
	}
	if err := repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{
		Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher",
	}); err != nil {
		t.Fatalf("UpdateHookwiseSettings() error = %v", err)
	}
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("ReconcileHookwiseOutbox(open) error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("PendingHookwiseEvents(open) = %#v, %v", events, err)
	}
	var openPayload struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(events[0].Payload, &openPayload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(openPayload.Summary, finding.Title) ||
		!strings.Contains(openPayload.Summary, finding.Host+":"+finding.Port) ||
		!strings.Contains(openPayload.Summary, "v1:stable-su") {
		t.Fatalf("readable open summary = %q", openPayload.Summary)
	}
	if err := repository.MarkHookwiseDelivered(t.Context(), events[0], 202); err != nil {
		t.Fatalf("MarkHookwiseDelivered() error = %v", err)
	}

	secondSnapshot := firstSnapshot
	secondSnapshot.ReportID = "summary-report-2"
	secondSnapshot.ScanEnd = firstEnd.Add(time.Hour)
	finding.Title = "Renamed by a later Greenbone feed"
	finding.Severity = 6.9
	if err := repository.SaveReportSnapshot(t.Context(), secondSnapshot, []FindingSnapshot{finding}); err != nil {
		t.Fatalf("SaveReportSnapshot(second) error = %v", err)
	}
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("ReconcileHookwiseOutbox(closed) error = %v", err)
	}
	events, err = repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 || events[0].EventType != "closed" {
		t.Fatalf("PendingHookwiseEvents(closed) = %#v, %v", events, err)
	}
	var closePayload struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(events[0].Payload, &closePayload); err != nil {
		t.Fatal(err)
	}
	if closePayload.Summary != openPayload.Summary {
		t.Errorf("close summary = %q, want original %q", closePayload.Summary, openPayload.Summary)
	}
}

func TestReconcileHookwiseOutboxMapsSeverityToConnectWisePriority(t *testing.T) {
	tests := []struct {
		name             string
		severity         float64
		expectedPriority string
	}{
		{name: "7.0 is high", severity: 7.0, expectedPriority: "P2-High"},
		{name: "8.49 is high", severity: 8.49, expectedPriority: "P2-High"},
		{name: "8.5 is critical", severity: 8.5, expectedPriority: "P1-Critical"},
		{name: "10.0 is critical", severity: 10.0, expectedPriority: "P1-Critical"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			repository := openTestStore(t)
			value := testCustomer(t, "connectwise-priority", []string{"10.59.0.1"})
			value.ConnectWiseCustomerName = "Acme Europe GmbH"
			if err := repository.CreateCustomer(t.Context(), value); err != nil {
				t.Fatalf("CreateCustomer() error = %v", err)
			}
			fixture := customerFixture{
				customerID: value.ID,
				scanEnd:    time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC),
			}
			saveTicketSnapshot(
				t,
				repository,
				fixture,
				"report-priority",
				fixture.scanEnd,
				testCase.severity,
			)
			if err := repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{
				Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher",
			}); err != nil {
				t.Fatalf("UpdateHookwiseSettings() error = %v", err)
			}
			if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
				t.Fatalf("ReconcileHookwiseOutbox() error = %v", err)
			}
			events, err := repository.PendingHookwiseEvents(t.Context(), 10)
			if err != nil || len(events) != 1 {
				t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
			}
			var payload struct {
				ConnectWiseCustomerName string  `json:"connectwise_customer_name"`
				Severity                string  `json:"severity"`
				SeveritySource          float64 `json:"severitysource"`
			}
			if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if payload.Severity != testCase.expectedPriority {
				t.Errorf("severity = %q, want %q", payload.Severity, testCase.expectedPriority)
			}
			if payload.SeveritySource != testCase.severity {
				t.Errorf("severitysource = %v, want %v", payload.SeveritySource, testCase.severity)
			}
			if payload.ConnectWiseCustomerName != value.ConnectWiseCustomerName {
				t.Errorf(
					"connectwise_customer_name = %q, want %q",
					payload.ConnectWiseCustomerName,
					value.ConnectWiseCustomerName,
				)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(events[0].Payload, &fields); err != nil {
				t.Fatalf("json.Unmarshal(fields) error = %v", err)
			}
			if _, found := fields["cid"]; found {
				t.Error("legacy cid field is still present in Hookwise payload")
			}
		})
	}
}

func TestRetryHookwiseFindingRearmsOnlyFailedEvent(t *testing.T) {
	repository, fixture, failed := hookwiseRetryTestFixture(t)
	if err := repository.MarkHookwiseFailed(t.Context(), failed, 503, "upstream unavailable"); err != nil {
		t.Fatalf("MarkHookwiseFailed() error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 0 {
		t.Fatalf("backed-off PendingHookwiseEvents() = %#v, %v", events, err)
	}

	if err := repository.RetryHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); err != nil {
		t.Fatalf("RetryHookwiseFinding() error = %v", err)
	}
	events, err = repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 || events[0].ID != failed.ID || events[0].Attempts != 1 {
		t.Fatalf("rearmed PendingHookwiseEvents() = %#v, %v", events, err)
	}
	if err := repository.RetryHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:missing",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RetryHookwiseFinding(non-failed) error = %v, want ErrNotFound", err)
	}
}

func TestRetryHookwiseFindingIgnoresFailedSiblingEvent(t *testing.T) {
	repository, fixture, openEvent := hookwiseRetryTestFixture(t)
	closeFinding(t, repository, fixture.customerID, RemediationResolved)
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("closing ReconcileHookwiseOutbox() error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("PendingHookwiseEvents() before failures = %#v, %v", events, err)
	}
	var closeEvent HookwiseEvent
	for _, event := range events {
		if event.EventType == "closed" {
			closeEvent = event
		}
	}
	if closeEvent.ID == 0 {
		t.Fatalf("closed sibling event not found in %#v", events)
	}
	if err := repository.MarkHookwiseFailed(t.Context(), openEvent, 503, "upstream unavailable"); err != nil {
		t.Fatalf("MarkHookwiseFailed() error = %v", err)
	}
	if err := repository.MarkHookwiseFailed(t.Context(), closeEvent, 503, "upstream unavailable"); err != nil {
		t.Fatalf("MarkHookwiseFailed(closed) error = %v", err)
	}

	if err := repository.RetryHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); err != nil {
		t.Fatalf("RetryHookwiseFinding() error = %v", err)
	}
	events, err = repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
	}
	if events[0].ID != closeEvent.ID || events[0].Attempts != 1 {
		t.Fatalf("retried events = %#v", events)
	}
}

func TestRecreateHookwiseFindingQueuesNewOpenGeneration(t *testing.T) {
	repository, fixture, delivered := hookwiseRetryTestFixture(t)
	if err := repository.RecreateHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecreateHookwiseFinding(queued) error = %v, want ErrNotFound", err)
	}
	if err := repository.MarkHookwiseDelivered(t.Context(), delivered, 202); err != nil {
		t.Fatalf("MarkHookwiseDelivered() error = %v", err)
	}

	if err := repository.RecreateHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); err != nil {
		t.Fatalf("RecreateHookwiseFinding(open) error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("PendingHookwiseEvents() = %#v, %v", events, err)
	}
	recreated := events[0]
	if recreated.ID == delivered.ID || recreated.Generation != delivered.Generation+1 ||
		recreated.EventType != "open" || recreated.Attempts != 0 {
		t.Fatalf("recreated event = %#v, delivered = %#v", recreated, delivered)
	}
	var payload struct {
		EventID string `json:"event_id"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(recreated.Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.EventID == "" || payload.State != "open" {
		t.Fatalf("recreated payload = %#v", payload)
	}
	findings, _, err := repository.CurrentFindings(t.Context(), FindingQuery{
		CustomerID: fixture.customerID,
	})
	if err != nil || len(findings) != 1 || findings[0].TicketState != "queued_open" {
		t.Fatalf("CurrentFindings() = %#v, %v", findings, err)
	}
	if err := repository.RecreateHookwiseFinding(
		t.Context(), fixture.customerID, "task-1", "v1:ticket",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecreateHookwiseFinding(repeated) error = %v, want ErrNotFound", err)
	}
}

func hookwiseRetryTestFixture(t *testing.T) (*Store, customerFixture, HookwiseEvent) {
	t.Helper()
	repository := openTestStore(t)
	value := testCustomer(t, "ticket-retry", []string{"10.58.0.1"})
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	if err := repository.CreateCustomer(t.Context(), value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	fixture := customerFixture{
		customerID: value.ID,
		scanEnd:    time.Date(2026, 8, 28, 11, 0, 0, 0, time.UTC),
	}
	saveTicketSnapshot(t, repository, fixture, "report-retry", fixture.scanEnd, 8.5)
	if err := repository.UpdateHookwiseSettings(t.Context(), customer.HookwiseSettings{
		Enabled: true, Endpoint: "https://hookwise.test/webhook", TokenCipher: "cipher",
	}); err != nil {
		t.Fatalf("UpdateHookwiseSettings() error = %v", err)
	}
	if err := repository.ReconcileHookwiseOutbox(t.Context()); err != nil {
		t.Fatalf("ReconcileHookwiseOutbox() error = %v", err)
	}
	events, err := repository.PendingHookwiseEvents(t.Context(), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("initial PendingHookwiseEvents() = %#v, %v", events, err)
	}
	return repository, fixture, events[0]
}

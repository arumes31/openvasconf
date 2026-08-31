package store

import (
	"errors"
	"testing"
)

func TestScanAlertLifecycleUsesAuditJournal(t *testing.T) {
	t.Parallel()
	repository := openTestStore(t)
	value := testCustomer(t, "scan-alert", []string{"10.0.0.1"})
	value.ConnectWiseCustomerName = "Acme Europe GmbH"
	if err := repository.CreateCustomer(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	alert := ScanAlert{
		CustomerID: value.ID,
		TaskID:     "task-1", TaskName: "scan-alert_PrivateIP_Task1",
		ReportID: "report-failed-1", Status: "Interrupted",
		Reason: "Greenbone scan ended with status \"Interrupted\"",
	}
	inserted, err := repository.RecordScanFailure(t.Context(), alert)
	if err != nil || !inserted {
		t.Fatalf("RecordScanFailure() = %t, %v", inserted, err)
	}
	inserted, err = repository.RecordScanFailure(t.Context(), alert)
	if err != nil || inserted {
		t.Fatalf("duplicate RecordScanFailure() = %t, %v", inserted, err)
	}

	alerts, err := repository.OpenScanAlerts(t.Context(), 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].ConnectWiseCustomerName != value.ConnectWiseCustomerName ||
		alerts[0].Reason != alert.Reason {
		t.Fatalf("alerts = %#v", alerts)
	}
	if err := repository.AcknowledgeScanAlert(t.Context(), alerts[0].ID); err != nil {
		t.Fatal(err)
	}
	alerts, err = repository.OpenScanAlerts(t.Context(), 20)
	if err != nil || len(alerts) != 0 {
		t.Fatalf("alerts after acknowledgement = %#v, %v", alerts, err)
	}
	events, err := repository.AuditEvents(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Action != scanAcknowledgedAction || events[1].Action != scanFailedAction {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestAcknowledgeScanAlertRejectsUnknownID(t *testing.T) {
	t.Parallel()
	repository := openTestStore(t)
	if err := repository.AcknowledgeScanAlert(t.Context(), 404); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

package report

import (
	"testing"
	"time"

	"openvasconf/internal/gmp"
)

func TestNormalizeComputesTotalsFromFindings(t *testing.T) {
	t.Parallel()

	report := gmp.ReportDetails{
		ID:        "report-1",
		TaskID:    "task-1",
		TaskName:  "task",
		Status:    "Done",
		ScanStart: time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC),
		ScanEnd:   time.Date(2026, 8, 22, 2, 45, 0, 0, time.UTC),
		// GMP-provided counts are deliberately wrong; computed counts win.
		High: 99,
		Results: []gmp.ReportResult{
			{
				NVTOID:       "oid-1",
				NVTName:      "NVT one",
				Host:         "10.0.0.1",
				Port:         "22/tcp",
				Threat:       "High",
				Severity:     9.8,
				QOD:          80,
				CVEs:         []string{"CVE-2021-1234"},
				Evidence:     "result evidence",
				CVSSVector:   "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				Summary:      "NVT summary",
				Insight:      "technical insight",
				Impact:       "security impact",
				Affected:     "affected product",
				SolutionType: "VendorFix",
				References:   []string{"url: https://greenbone.example/nvt"},
			},
			{
				NVTOID:   "oid-2",
				Host:     "10.0.0.2",
				Port:     "80/tcp",
				Threat:   "Medium",
				Severity: 5.0,
			},
			{
				Name:     "detection only",
				Host:     "10.0.0.3",
				Severity: 0,
			},
		},
	}

	snapshot, findings := Normalize("customer-1", report)
	if snapshot.ReportID != "report-1" || snapshot.CustomerID != "customer-1" {
		t.Errorf("snapshot identity = %#v", snapshot)
	}
	if snapshot.CountHigh != 1 || snapshot.CountMedium != 1 || snapshot.CountLog != 1 {
		t.Errorf("counts = H%d M%d Log%d", snapshot.CountHigh, snapshot.CountMedium, snapshot.CountLog)
	}
	if snapshot.SeverityMax != 9.8 || snapshot.FindingCount != 3 {
		t.Errorf("max=%v count=%d", snapshot.SeverityMax, snapshot.FindingCount)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Fingerprint != Fingerprint("customer-1", "oid-1", "10.0.0.1", "22/tcp", "") {
		t.Errorf("finding fingerprint = %q", findings[0].Fingerprint)
	}
	if findings[2].Threat != "Log" || findings[2].Title != "detection only" {
		t.Errorf("derived threat/title = %#v", findings[2])
	}
	if findings[0].Evidence != "result evidence" ||
		findings[0].CVSSVector != "AV:N/AC:L/Au:N/C:P/I:P/A:P" ||
		findings[0].Summary != "NVT summary" ||
		findings[0].Insight != "technical insight" ||
		findings[0].Impact != "security impact" ||
		findings[0].Affected != "affected product" ||
		findings[0].SolutionType != "VendorFix" ||
		len(findings[0].References) != 1 {
		t.Errorf("normalized Greenbone metadata = %#v", findings[0])
	}
}

func TestNormalizeFallsBackToGMPCounts(t *testing.T) {
	t.Parallel()

	report := gmp.ReportDetails{
		ID:       "report-log-only",
		Status:   "Done",
		Severity: 4.3,
		High:     1,
		Medium:   2,
		Low:      3,
		Log:      40,
		FalsePos: 1,
	}
	snapshot, findings := Normalize("customer-1", report)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
	if snapshot.CountHigh != 1 || snapshot.CountMedium != 2 || snapshot.CountLow != 3 ||
		snapshot.CountLog != 40 || snapshot.CountFalsePos != 1 {
		t.Errorf("fallback counts = %#v", snapshot)
	}
	if snapshot.FindingCount != 47 || snapshot.SeverityMax != 4.3 {
		t.Errorf("fallback totals = count %d max %v", snapshot.FindingCount, snapshot.SeverityMax)
	}
}

func TestSanitizeDiagnostic(t *testing.T) {
	t.Parallel()

	long := make([]byte, 0, 2000)
	for range 200 {
		long = append(long, "payload<result> "...)
	}
	diagnostic := sanitizeDiagnostic(errorString(string(long)))
	if len([]rune(diagnostic)) > maxDiagnosticLength {
		t.Errorf("diagnostic length = %d, want <= %d", len(diagnostic), maxDiagnosticLength)
	}
	messy := sanitizeDiagnostic(errorString("line one\n  line\ttwo"))
	if messy != "line one line two" {
		t.Errorf("diagnostic not folded: %q", messy)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

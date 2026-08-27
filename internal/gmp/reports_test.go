package gmp

import (
	"context"
	"encoding/xml"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

const testReportXML = `<get_reports_response status="200" status_text="OK">` +
	`<report id="report-1" format_id="d5da2541-95b7-4d10-b0c9-7f0f0a0a0a0a">` +
	`<name>2026-08-22 scan</name>` +
	`<report id="report-1">` +
	`<task id="task-1"><name>testcomp1_PrivateIP_Task1</name></task>` +
	`<scan_start>2026-08-22T02:00:00Z</scan_start>` +
	`<scan_end>2026-08-22T02:45:00Z</scan_end>` +
	`<scan_run_status>Done</scan_run_status>` +
	`<severity>9.8</severity>` +
	`<result_count>2<filtered>2</filtered><debug>0</debug><hole>1</hole>` +
	`<info>0</info><log>1</log><warning>0</warning><false_positive>0</false_positive>` +
	`</result_count>` +
	`<results start="1" max="-1" details="1">` +
	`<result id="result-1">` +
	`<name>OpenSSH Weak Encryption</name>` +
	`<host>10.1.0.5<asset asset_id="asset-1"/></host>` +
	`<port>22/tcp</port>` +
	`<nvt oid="1.3.6.1.4.1.25623.1.0.100001">` +
	`<name>OpenSSH Weak Encryption Algorithms</name>` +
	`<tags>cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:P/A:P|` +
	`solution=Update OpenSSH to the latest available version|` +
	`cve=CVE-2021-1234, CVE-2021-5678|summary=weak ciphers</tags>` +
	`</nvt>` +
	`<threat>High</threat>` +
	`<severity>9.8</severity>` +
	`<qod><value>80</value><type>remote_banner</type></qod>` +
	`<description>The remote SSH server supports weak encryption algorithms.</description>` +
	`</result>` +
	`<result id="result-2">` +
	`<name>nginx Version Detection</name>` +
	`<host>10.1.0.6</host>` +
	`<port>80/tcp</port>` +
	`<nvt oid="1.3.6.1.4.1.25623.1.0.100002"><name>nginx Detection</name>` +
	`<tags>summary=version detection</tags></nvt>` +
	`<threat>Log</threat>` +
	`<severity>0.0</severity>` +
	`<qod><value>95</value></qod>` +
	`<description>nginx was detected.</description>` +
	`<solution type="WillNotFix">No solution available</solution>` +
	`</result>` +
	`</results>` +
	`</report>` +
	`</report>` +
	`</get_reports_response>`

func reportLimits() ReportLimits {
	return ReportLimits{MaxBytes: 64 << 20, MaxResults: 50000}
}

func TestClientReportParsesStreamedResults(t *testing.T) {
	t.Parallel()

	client := fakeClient(t, []string{testReportXML}, nil)
	report, err := client.Report(t.Context(), "report-1", reportLimits())
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if report.ID != "report-1" || report.TaskID != "task-1" ||
		report.TaskName != "testcomp1_PrivateIP_Task1" {
		t.Errorf("report identity = %#v", report)
	}
	if report.Status != "Done" || report.Severity != 9.8 {
		t.Errorf("report status/severity = %q/%v", report.Status, report.Severity)
	}
	if report.ScanStart.IsZero() || report.ScanEnd.IsZero() {
		t.Errorf("scan times not parsed: %#v", report)
	}
	if report.High != 1 || report.Log != 1 || report.Medium != 0 {
		t.Errorf("result counts = H%d M%d L%d Log%d", report.High, report.Medium, report.Low, report.Log)
	}
	if len(report.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(report.Results))
	}

	first := report.Results[0]
	if first.NVTOID != "1.3.6.1.4.1.25623.1.0.100001" || first.Host != "10.1.0.5" ||
		first.Port != "22/tcp" || first.Threat != "High" || first.Severity != 9.8 || first.QOD != 80 {
		t.Errorf("first result = %#v", first)
	}
	if len(first.CVEs) != 2 || first.CVEs[0] != "CVE-2021-1234" || first.CVEs[1] != "CVE-2021-5678" {
		t.Errorf("cves = %#v", first.CVEs)
	}
	if first.Remediation != "Update OpenSSH to the latest available version" {
		t.Errorf("remediation = %q", first.Remediation)
	}

	second := report.Results[1]
	if second.Remediation != "No solution available" {
		t.Errorf("solution element fallback = %q", second.Remediation)
	}
}

func TestClientReportUsesReportSpecificTimeout(t *testing.T) {
	t.Parallel()

	clientSide, serverSide := net.Pipe()
	dial := func(context.Context, string, string) (net.Conn, error) {
		return clientSide, nil
	}
	client := NewWithDialer("admin", "secret", 20*time.Millisecond, dial).
		WithReportTimeout(200 * time.Millisecond)

	go func() {
		defer func() { _ = serverSide.Close() }()
		decoder := xml.NewDecoder(serverSide)
		for requestIndex := range 2 {
			var request struct{ XMLName xml.Name }
			if err := decoder.Decode(&request); err != nil {
				return
			}
			if requestIndex == 0 {
				_, _ = serverSide.Write([]byte(
					`<authenticate_response status="200" status_text="OK"/>`,
				))
				continue
			}
			time.Sleep(50 * time.Millisecond)
			_, _ = serverSide.Write([]byte(testReportXML))
		}
	}()

	if _, err := client.Report(t.Context(), "report-1", reportLimits()); err != nil {
		t.Fatalf("Report() error = %v, want report-specific timeout to allow response", err)
	}
}

func TestClientReportMalformedStream(t *testing.T) {
	t.Parallel()

	truncated := testReportXML[:len(testReportXML)/2]
	client := fakeClient(t, []string{truncated}, nil)
	_, err := client.Report(t.Context(), "report-1", reportLimits())
	if err == nil {
		t.Fatal("Report() error = nil, want stream error")
	}
}

func TestClientReportToleratesMissingFields(t *testing.T) {
	t.Parallel()

	partial := `<get_reports_response status="200" status_text="OK">` +
		`<report id="report-2"><report id="report-2">` +
		`<results><result id="result-x"><name>partial</name></result></results>` +
		`</report></report></get_reports_response>`
	client := fakeClient(t, []string{partial}, nil)
	report, err := client.Report(t.Context(), "report-2", reportLimits())
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(report.Results))
	}
	result := report.Results[0]
	if result.Name != "partial" || result.Severity != 0 || result.QOD != 0 ||
		result.NVTOID != "" || len(result.CVEs) != 0 || result.Remediation != "" {
		t.Errorf("partial result = %#v", result)
	}
}

func TestClientReportEnforcesResultLimit(t *testing.T) {
	t.Parallel()

	client := fakeClient(t, []string{testReportXML}, nil)
	limits := reportLimits()
	limits.MaxResults = 1
	_, err := client.Report(t.Context(), "report-1", limits)
	if err == nil || !strings.Contains(err.Error(), "limit of 1 results") {
		t.Fatalf("Report() error = %v, want result limit error", err)
	}
}

func TestClientReportEnforcesByteLimit(t *testing.T) {
	t.Parallel()

	client := fakeClient(t, []string{testReportXML}, nil)
	limits := reportLimits()
	limits.MaxBytes = 256
	_, err := client.Report(t.Context(), "report-1", limits)
	if !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("Report() error = %v, want byte limit error", err)
	}
}

func TestClientReportEmpty(t *testing.T) {
	t.Parallel()

	empty := `<get_reports_response status="200" status_text="OK"></get_reports_response>`
	client := fakeClient(t, []string{empty}, nil)
	report, err := client.Report(t.Context(), "missing", reportLimits())
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if report.ID != "" || len(report.Results) != 0 {
		t.Errorf("empty report = %#v", report)
	}
}

func TestClientReportProtocolError(t *testing.T) {
	t.Parallel()

	client := fakeClient(
		t,
		[]string{`<get_reports_response status="404" status_text="Failed to find report"/>`},
		nil,
	)
	_, err := client.Report(t.Context(), "missing", reportLimits())
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Status != "404" {
		t.Fatalf("Report() error = %v, want 404 protocol error", err)
	}
}

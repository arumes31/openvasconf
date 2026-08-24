package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testExportMeta() ExportMeta {
	return ExportMeta{
		SnapshotID:   7,
		ReportID:     "report-uuid-1",
		CustomerName: "testcomp1",
		TaskName:     "testcomp1_PrivateIP_Task1",
		ScanStart:    time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC),
		ScanEnd:      time.Date(2026, 8, 22, 2, 45, 0, 0, time.UTC),
		Filters:      map[string]string{"severity": "high"},
		ExportedAt:   time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC),
		Truncated:    false,
	}
}

func testExportRows() []ExportRow {
	due := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return []ExportRow{
		{
			Fingerprint:      "v1:aaa",
			NVTOID:           "1.3.6.1.4.1.25623.1.0.100001",
			Title:            "Weak cipher, deprecated (TLS)",
			Host:             "10.1.0.5",
			Port:             "443/tcp",
			Severity:         9.8,
			Threat:           "High",
			QOD:              80,
			CVEs:             []string{"CVE-2021-1234"},
			Lifecycle:        LifecycleNew,
			Disposition:      "active",
			RemediationState: "in_progress",
			RemediationOwner: "ops-team",
			DueDate:          &due,
			SLAState:         SLAStateDueSoon,
		},
		{
			Fingerprint: "v1:bbb",
			NVTOID:      "1.3.6.1.4.1.25623.1.0.100002",
			Title: `Quoted "title"
with newline`,
			Host:             "10.1.0.6",
			Port:             "22/tcp",
			Severity:         4.3,
			Threat:           "Medium",
			QOD:              95,
			Lifecycle:        LifecycleRecurring,
			Disposition:      "accepted_risk",
			RemediationState: "open",
			SLAState:         SLAStateOnTrack,
		},
	}
}

func TestCSVExportEscapingAndTruncation(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WriteCSVExport(&buf, testExportRows(), true); err != nil {
		t.Fatalf("WriteCSVExport() error = %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse error = %v", err)
	}
	if len(records) != 1+2+1 {
		t.Fatalf("records = %d, want header + 2 rows + marker", len(records))
	}
	if records[0][0] != "fingerprint" || records[0][15] != "sla_state" {
		t.Errorf("header = %#v", records[0])
	}
	if records[1][2] != "Weak cipher, deprecated (TLS)" {
		t.Errorf("comma field = %q", records[1][2])
	}
	if records[2][2] != "Quoted \"title\"\nwith newline" {
		t.Errorf("quoted/newline field = %q", records[2][2])
	}
	if records[1][14] != "2026-09-01" || records[1][12] != "in_progress" {
		t.Errorf("due date/remediation = %q/%q", records[1][14], records[1][12])
	}
	if !strings.Contains(records[3][0], "TRUNCATED") {
		t.Errorf("truncation marker = %#v", records[3])
	}
}

func TestCSVExportFormulaInjectionGuard(t *testing.T) {
	t.Parallel()

	rows := []ExportRow{{
		Fingerprint: "v1:x",
		Title:       "=HYPERLINK(\"http://evil\")",
		Host:        "+cmd",
		Threat:      "High",
	}}
	var buf bytes.Buffer
	if err := WriteCSVExport(&buf, rows, false); err != nil {
		t.Fatalf("WriteCSVExport() error = %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse error = %v", err)
	}
	if !strings.HasPrefix(records[1][2], "'=") {
		t.Errorf("formula title not guarded: %q", records[1][2])
	}
	if !strings.HasPrefix(records[1][3], "'+") {
		t.Errorf("formula host not guarded: %q", records[1][3])
	}
}

func TestJSONExportShape(t *testing.T) {
	t.Parallel()

	meta := testExportMeta()
	meta.Truncated = true
	var buf bytes.Buffer
	if err := WriteJSONExport(&buf, meta, testExportRows()); err != nil {
		t.Fatalf("WriteJSONExport() error = %v", err)
	}
	var document struct {
		Meta struct {
			ReportID  string `json:"report_id"`
			Truncated bool   `json:"truncated"`
			Filters   map[string]string
		} `json:"meta"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &document); err != nil {
		t.Fatalf("json parse error = %v\n%s", err, buf.String())
	}
	if document.Meta.ReportID != "report-uuid-1" || !document.Meta.Truncated {
		t.Errorf("meta = %#v", document.Meta)
	}
	if document.Meta.Filters["severity"] != "high" {
		t.Errorf("filters = %#v", document.Meta.Filters)
	}
	if len(document.Findings) != 2 || document.Findings[0]["fingerprint"] != "v1:aaa" {
		t.Errorf("findings = %#v", document.Findings)
	}
	if document.Findings[0]["due_date"] == nil || document.Findings[1]["due_date"] != nil {
		t.Errorf("due date presence wrong: %#v", document.Findings)
	}
}

func TestSARIFExportStructure(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WriteSARIFExport(&buf, testExportMeta(), testExportRows()); err != nil {
		t.Fatalf("WriteSARIFExport() error = %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(buf.Bytes(), &document); err != nil {
		t.Fatalf("sarif parse error = %v", err)
	}
	if document["version"] != "2.1.0" || document["$schema"] == "" {
		t.Errorf("sarif header = %#v", document)
	}
	runs, _ := document["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %#v", document["runs"])
	}
	run, _ := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "openvasconf" {
		t.Errorf("driver = %#v", driver)
	}
	rules, _ := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("rules = %d, want one per distinct NVT oid", len(rules))
	}
	results, _ := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
	first, _ := results[0].(map[string]any)
	if first["ruleId"] != "1.3.6.1.4.1.25623.1.0.100001" || first["level"] != "error" {
		t.Errorf("first result = %#v", first)
	}
	fingerprints, _ := first["partialFingerprints"].(map[string]any)
	if fingerprints["openvasconf/v1"] != "v1:aaa" {
		t.Errorf("partialFingerprints = %#v", fingerprints)
	}
	location := first["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if location["address"].(map[string]any)["fullyQualifiedName"] != "10.1.0.5" {
		t.Errorf("location = %#v", location)
	}
	second, _ := results[1].(map[string]any)
	if second["level"] != "warning" {
		t.Errorf("medium severity level = %v, want warning", second["level"])
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	t.Parallel()

	cases := map[float64]string{9.8: "error", 7.0: "error", 4.0: "warning", 0.1: "note", 0: "none"}
	for severity, want := range cases {
		if got := sarifLevel(severity); got != want {
			t.Errorf("sarifLevel(%v) = %q, want %q", severity, got, want)
		}
	}
}

func TestPDFExportStructure(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WritePDFExport(&buf, testExportMeta(), testExportRows()); err != nil {
		t.Fatalf("WritePDFExport() error = %v", err)
	}
	output := buf.Bytes()
	if !bytes.HasPrefix(output, []byte("%PDF-")) {
		t.Fatal("output misses the PDF magic header")
	}
	if !bytes.HasSuffix(bytes.TrimRight(output, "\n"), []byte("%%EOF")) {
		t.Fatal("output misses the EOF trailer")
	}

	// The startxref offset must point at the xref table, and every xref entry
	// must point at its "N 0 obj" header.
	marker := []byte("startxref\n")
	index := bytes.LastIndex(output, marker)
	if index < 0 {
		t.Fatal("startxref missing")
	}
	var xrefOffset int
	if _, err := fmt.Sscanf(string(output[index+len(marker):]), "%d", &xrefOffset); err != nil {
		t.Fatalf("parsing startxref: %v", err)
	}
	if !bytes.HasPrefix(output[xrefOffset:], []byte("xref\n")) {
		t.Fatalf("offset %d does not point at xref table", xrefOffset)
	}
	lines := bytes.Split(output[xrefOffset:], []byte("\n"))
	var count int
	if _, err := fmt.Sscanf(string(lines[1]), "0 %d", &count); err != nil {
		t.Fatalf("parsing xref header: %v", err)
	}
	for entry := 1; entry < count; entry++ {
		var offset int
		var generation int
		var kind string
		fields := strings.Fields(string(lines[2+entry]))
		if len(fields) != 3 {
			t.Fatalf("xref entry %d malformed: %q", entry, lines[2+entry])
		}
		if _, err := fmt.Sscanf(fields[0], "%d", &offset); err != nil {
			t.Fatalf("xref entry %d offset: %v", entry, err)
		}
		if _, err := fmt.Sscanf(fields[1], "%d", &generation); err != nil {
			t.Fatalf("xref entry %d generation: %v", entry, err)
		}
		kind = fields[2]
		if kind != "n" {
			t.Fatalf("xref entry %d kind = %q", entry, kind)
		}
		expected := []byte(fmt.Sprintf("%d 0 obj", entry))
		if !bytes.HasPrefix(output[offset:], expected) {
			t.Errorf("xref entry %d offset %d does not point at %q", entry, offset, expected)
		}
	}
}

func TestPDFExportManyRowsPaginates(t *testing.T) {
	t.Parallel()

	rows := make([]ExportRow, 0, 200)
	for range 200 {
		rows = append(rows, ExportRow{
			Fingerprint: "v1:row",
			Title:       "finding with a somewhat longer title to fill the page",
			Host:        "10.0.0.1",
			Port:        "443/tcp",
			Severity:    9.8,
			Threat:      "High",
		})
	}
	var buf bytes.Buffer
	if err := WritePDFExport(&buf, testExportMeta(), rows); err != nil {
		t.Fatalf("WritePDFExport() error = %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Fatal("invalid pdf output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("more findings not shown")) {
		t.Error("missing row-cap note")
	}
}

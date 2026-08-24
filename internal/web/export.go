package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"openvasconf/internal/networkplan"
	"openvasconf/internal/report"
)

// exportFormats maps the format parameter to content type and file extension.
var exportFormats = map[string]struct {
	contentType string
	extension   string
}{
	"csv":   {"text/csv; charset=utf-8", "csv"},
	"json":  {"application/json", "json"},
	"sarif": {"application/sarif+json", "sarif.json"},
	"pdf":   {"application/pdf", "pdf"},
}

// reportExport streams the findings of one snapshot in the requested format,
// honoring the same filters as the report detail page. Rows beyond the
// configured row limit are cut and marked as truncated; output beyond the
// byte limit is cut off cleanly and logged.
func (s *Server) reportExport(response http.ResponseWriter, request *http.Request) {
	snapshot, found := s.loadSnapshot(response, request)
	if !found {
		return
	}
	format, ok := exportFormats[request.URL.Query().Get("format")]
	if !ok {
		http.Error(response, "unknown export format (want csv, json, sarif, or pdf)", http.StatusBadRequest)
		return
	}

	rows, _, _, err := s.reportRows(request.Context(), snapshot)
	if err != nil {
		s.internalError(response, err)
		return
	}
	filter := filterFromQuery(request)
	exportRows := make([]report.ExportRow, 0, len(rows))
	for _, row := range rows {
		if matchesReportFilter(row, filter) {
			exportRows = append(exportRows, exportRow(row))
		}
	}
	truncated := false
	if len(exportRows) > s.exportMaxRows {
		exportRows = exportRows[:s.exportMaxRows]
		truncated = true
		s.logger.Warn(
			"export truncated at row limit",
			"report_id", snapshot.ReportID,
			"limit", s.exportMaxRows,
		)
	}

	meta := report.ExportMeta{
		SnapshotID:   snapshot.ID,
		ReportID:     snapshot.ReportID,
		CustomerName: snapshot.CustomerName,
		TaskName:     snapshot.TaskName,
		ScanStart:    snapshot.ScanStart,
		ScanEnd:      snapshot.ScanEnd,
		Filters:      activeFilters(filter),
		ExportedAt:   time.Now(),
		Truncated:    truncated,
	}

	response.Header().Set("Content-Type", format.contentType)
	response.Header().Set(
		"Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", exportFilename(snapshot.CustomerName, snapshot.ReportID, format.extension)),
	)
	writer := &byteCapWriter{writer: response, remaining: s.exportMaxBytes}
	var exportErr error
	switch request.URL.Query().Get("format") {
	case "csv":
		exportErr = report.WriteCSVExport(writer, exportRows, truncated)
	case "json":
		exportErr = report.WriteJSONExport(writer, meta, exportRows)
	case "sarif":
		exportErr = report.WriteSARIFExport(writer, meta, exportRows)
	case "pdf":
		exportErr = report.WritePDFExport(writer, meta, exportRows)
	}
	if writer.capped {
		s.logger.Warn(
			"export cut off at byte limit",
			"report_id", snapshot.ReportID,
			"limit", s.exportMaxBytes,
		)
	}
	if exportErr != nil && !errors.Is(exportErr, errExportByteLimit) {
		s.logger.Error("export failed", "report_id", snapshot.ReportID, "error", exportErr)
	}
}

func exportRow(row findingView) report.ExportRow {
	return report.ExportRow{
		Fingerprint:      row.Fingerprint,
		NVTOID:           row.NVTOID,
		Title:            row.Title,
		Host:             row.Host,
		Port:             row.Port,
		Location:         row.Location,
		Severity:         row.Severity,
		Threat:           row.Threat,
		QOD:              row.QOD,
		CVEs:             row.CVEs,
		Lifecycle:        row.Lifecycle,
		Disposition:      row.Disposition,
		RemediationState: row.RemediationState,
		RemediationOwner: row.RemediationOwner,
		DueDate:          row.DueDate,
		SLAState:         row.SLAState,
	}
}

// activeFilters records the non-empty filters in the export metadata.
func activeFilters(filter reportFilter) map[string]string {
	result := make(map[string]string)
	for key, value := range map[string]string{
		"severity":    filter.Severity,
		"host":        filter.Host,
		"port":        filter.Port,
		"lifecycle":   filter.Lifecycle,
		"disposition": filter.Disposition,
		"owner":       filter.Owner,
		"remediation": filter.Remediation,
		"sla":         filter.SLA,
	} {
		if value != "" {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func exportFilename(customerName, reportID, extension string) string {
	base := networkplan.SafeName(customerName)
	if base == "" {
		base = "report"
	}
	name := base + "-" + reportID + "." + extension
	return strings.ReplaceAll(name, `"`, "")
}

var errExportByteLimit = errors.New("web: export byte limit reached")

// byteCapWriter fails writes with errExportByteLimit once the byte budget is
// exhausted, so encoders abort instead of streaming unbounded output.
type byteCapWriter struct {
	writer    io.Writer
	remaining int64
	capped    bool
}

func (w *byteCapWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		w.capped = true
		return 0, errExportByteLimit
	}
	if int64(len(p)) > w.remaining {
		w.capped = true
		written, err := w.writer.Write(p[:w.remaining])
		w.remaining -= int64(written)
		if err != nil {
			return written, err
		}
		return written, errExportByteLimit
	}
	written, err := w.writer.Write(p)
	w.remaining -= int64(written)
	return written, err
}

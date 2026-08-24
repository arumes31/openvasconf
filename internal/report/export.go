package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ExportRow is one finding row prepared for export, combining the immutable
// snapshot finding with lifecycle, annotation, and SLA state.
type ExportRow struct {
	Fingerprint      string     `json:"fingerprint"`
	NVTOID           string     `json:"nvt_oid"`
	Title            string     `json:"title"`
	Host             string     `json:"host"`
	Port             string     `json:"port"`
	Location         string     `json:"location"`
	Severity         float64    `json:"severity"`
	Threat           string     `json:"threat"`
	QOD              int        `json:"qod"`
	CVEs             []string   `json:"cves,omitempty"`
	Lifecycle        string     `json:"lifecycle"`
	Disposition      string     `json:"disposition"`
	RemediationState string     `json:"remediation_state"`
	RemediationOwner string     `json:"remediation_owner,omitempty"`
	DueDate          *time.Time `json:"due_date,omitempty"`
	SLAState         string     `json:"sla_state"`
}

// ExportMeta describes the exported snapshot and the active filters.
type ExportMeta struct {
	SnapshotID   int64             `json:"snapshot_id"`
	ReportID     string            `json:"report_id"`
	CustomerName string            `json:"customer_name"`
	TaskName     string            `json:"task_name"`
	ScanStart    time.Time         `json:"scan_start,omitempty"`
	ScanEnd      time.Time         `json:"scan_end,omitempty"`
	Filters      map[string]string `json:"filters,omitempty"`
	ExportedAt   time.Time         `json:"exported_at"`
	Truncated    bool              `json:"truncated"`
}

var csvHeader = []string{
	"fingerprint", "nvt_oid", "title", "host", "port", "location",
	"severity", "threat", "qod", "cves", "lifecycle", "disposition",
	"remediation_state", "remediation_owner", "due_date", "sla_state",
}

// WriteCSVExport streams findings as RFC 4180 CSV. When truncated is true a
// final marker row documents that the row limit cut the export.
func WriteCSVExport(w io.Writer, rows []ExportRow, truncated bool) error {
	writer := csv.NewWriter(w)
	if err := writer.Write(csvHeader); err != nil {
		return fmt.Errorf("report: writing csv header: %w", err)
	}
	for _, row := range rows {
		if err := writer.Write(csvRecord(row)); err != nil {
			return fmt.Errorf("report: writing csv record: %w", err)
		}
	}
	if truncated {
		marker := make([]string, len(csvHeader))
		marker[0] = "TRUNCATED: export row limit reached"
		if err := writer.Write(marker); err != nil {
			return fmt.Errorf("report: writing csv truncation marker: %w", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("report: flushing csv: %w", err)
	}
	return nil
}

func csvRecord(row ExportRow) []string {
	dueDate := ""
	if row.DueDate != nil {
		dueDate = row.DueDate.Format("2006-01-02")
	}
	return []string{
		csvSafe(row.Fingerprint),
		csvSafe(row.NVTOID),
		csvSafe(row.Title),
		csvSafe(row.Host),
		csvSafe(row.Port),
		csvSafe(row.Location),
		strconv.FormatFloat(row.Severity, 'f', 1, 64),
		csvSafe(row.Threat),
		strconv.Itoa(row.QOD),
		csvSafe(strings.Join(row.CVEs, ",")),
		csvSafe(row.Lifecycle),
		csvSafe(row.Disposition),
		csvSafe(row.RemediationState),
		csvSafe(row.RemediationOwner),
		dueDate,
		csvSafe(row.SLAState),
	}
}

// csvSafe guards against spreadsheet formula injection: a leading =, +, -, or
// @ would be evaluated as a formula when the CSV is opened in a spreadsheet,
// so the field is prefixed with a single quote.
func csvSafe(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	}
	return value
}

// WriteJSONExport streams findings as a JSON document of the shape
// {"meta": {...}, "findings": [...]}.
func WriteJSONExport(w io.Writer, meta ExportMeta, rows []ExportRow) error {
	if _, err := io.WriteString(w, `{"meta":`); err != nil {
		return err
	}
	if err := json.NewEncoder(w).Encode(meta); err != nil {
		return fmt.Errorf("report: writing json meta: %w", err)
	}
	if _, err := io.WriteString(w, `,"findings":[`); err != nil {
		return err
	}
	for index, row := range rows {
		if index > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := json.NewEncoder(w).Encode(row); err != nil {
			return fmt.Errorf("report: writing json finding: %w", err)
		}
	}
	if _, err := io.WriteString(w, "]}\n"); err != nil {
		return err
	}
	return nil
}

// SARIF 2.1.0 document shape.
type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool       `json:"tool"`
	Results    []sarifResult   `json:"results"`
	Properties sarifProperties `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string      `json:"id"`
	ShortDescription sarifText   `json:"shortDescription,omitempty"`
	Properties       sarifRuleKV `json:"properties,omitempty"`
}

type sarifRuleKV struct {
	Threat string `json:"threat,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Locations           []sarifLocation   `json:"locations"`
	Properties          sarifResultProps  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	Address    sarifAddress   `json:"address"`
	Properties sarifAddrProps `json:"properties,omitempty"`
}

type sarifAddress struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

type sarifAddrProps struct {
	Port     string `json:"port,omitempty"`
	Location string `json:"location,omitempty"`
}

type sarifResultProps struct {
	Severity         float64  `json:"severity"`
	Threat           string   `json:"threat,omitempty"`
	QOD              int      `json:"qod,omitempty"`
	CVEs             []string `json:"cves,omitempty"`
	Lifecycle        string   `json:"lifecycle,omitempty"`
	Disposition      string   `json:"disposition,omitempty"`
	RemediationState string   `json:"remediationState,omitempty"`
	RemediationOwner string   `json:"remediationOwner,omitempty"`
	DueDate          string   `json:"dueDate,omitempty"`
	SLAState         string   `json:"slaState,omitempty"`
}

type sarifProperties struct {
	ReportID   string `json:"reportId,omitempty"`
	Customer   string `json:"customer,omitempty"`
	Truncated  bool   `json:"truncated"`
	ExportedAt string `json:"exportedAt,omitempty"`
}

// WriteSARIFExport writes findings as a SARIF 2.1.0 document. The stable
// finding fingerprint is the result identity (partialFingerprints).
func WriteSARIFExport(w io.Writer, meta ExportMeta, rows []ExportRow) error {
	rules := make(map[string]ExportRow)
	for _, row := range rows {
		if _, found := rules[row.NVTOID]; !found {
			rules[row.NVTOID] = row
		}
	}
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:    "openvasconf",
			Version: "1.0.0",
			Rules:   make([]sarifRule, 0, len(rules)),
		}},
		Results: make([]sarifResult, 0, len(rows)),
		Properties: sarifProperties{
			ReportID:   meta.ReportID,
			Customer:   meta.CustomerName,
			Truncated:  meta.Truncated,
			ExportedAt: meta.ExportedAt.UTC().Format(time.RFC3339),
		},
	}
	for oid, row := range rules {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               oid,
			ShortDescription: sarifText{Text: row.Title},
			Properties:       sarifRuleKV{Threat: row.Threat},
		})
	}
	for _, row := range rows {
		props := sarifResultProps{
			Severity:         row.Severity,
			Threat:           row.Threat,
			QOD:              row.QOD,
			CVEs:             row.CVEs,
			Lifecycle:        row.Lifecycle,
			Disposition:      row.Disposition,
			RemediationState: row.RemediationState,
			RemediationOwner: row.RemediationOwner,
			SLAState:         row.SLAState,
		}
		if row.DueDate != nil {
			props.DueDate = row.DueDate.Format("2006-01-02")
		}
		run.Results = append(run.Results, sarifResult{
			RuleID:  row.NVTOID,
			Level:   sarifLevel(row.Severity),
			Message: sarifText{Text: row.Title},
			PartialFingerprints: map[string]string{
				"openvasconf/v1": row.Fingerprint,
			},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				Address:    sarifAddress{FullyQualifiedName: row.Host},
				Properties: sarifAddrProps{Port: row.Port, Location: row.Location},
			}}},
			Properties: props,
		})
	}
	document := sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("report: writing sarif document: %w", err)
	}
	return nil
}

// sarifLevel maps severity scores to SARIF levels.
func sarifLevel(severity float64) string {
	switch {
	case severity >= 7.0:
		return "error"
	case severity >= 4.0:
		return "warning"
	case severity > 0:
		return "note"
	default:
		return "none"
	}
}

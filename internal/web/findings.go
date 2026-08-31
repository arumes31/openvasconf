package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openvasconf/internal/store"
)

func (s *Server) findingsList(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	filter := findingFilterFromRequest(request, 100)
	rows, total, err := s.repository.CurrentFindings(request.Context(), filter)
	if err != nil {
		s.internalError(response, err)
		return
	}
	metrics, err := s.repository.CurrentFindingMetrics(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	customers, err := s.repository.Customers(request.Context(), false)
	if err != nil {
		s.internalError(response, err)
		return
	}
	pages := max((total+filter.PageSize-1)/filter.PageSize, 1)
	s.render(response, request, "findings.html", pageData{
		Title:           "Current findings",
		Authenticated:   true,
		CurrentFindings: rows,
		FindingMetrics:  metrics,
		FindingQuery:    filter,
		FindingTotal:    total,
		FindingPage:     filter.Page,
		FindingPages:    pages,
		Customers:       customers,
		Notice:          noticeText(query.Get("notice")),
	})
}

type currentFindingExport struct {
	ExportedAt time.Time                 `json:"exported_at"`
	Total      int                       `json:"total"`
	Exported   int                       `json:"exported"`
	Truncated  bool                      `json:"truncated"`
	Filters    map[string]string         `json:"filters,omitempty"`
	Sort       []string                  `json:"sort"`
	Findings   []currentFindingExportRow `json:"findings"`
}

type currentFindingExportRow struct {
	CustomerID       string    `json:"customer_id"`
	CustomerName     string    `json:"customer_name"`
	CID              string    `json:"cid,omitempty"`
	TaskID           string    `json:"task_id"`
	TaskName         string    `json:"task_name"`
	SnapshotID       int64     `json:"snapshot_id"`
	Fingerprint      string    `json:"fingerprint"`
	NVTOID           string    `json:"nvt_oid"`
	Title            string    `json:"title"`
	Host             string    `json:"host"`
	Port             string    `json:"port,omitempty"`
	Location         string    `json:"location,omitempty"`
	Severity         float64   `json:"severity"`
	Threat           string    `json:"threat"`
	QOD              int       `json:"qod"`
	CVEs             []string  `json:"cves"`
	Remediation      string    `json:"remediation,omitempty"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	Lifecycle        string    `json:"lifecycle"`
	Disposition      string    `json:"disposition"`
	Justification    string    `json:"justification,omitempty"`
	RemediationState string    `json:"remediation_state"`
	TicketState      string    `json:"ticket_state"`
}

func (s *Server) findingsJSONExport(response http.ResponseWriter, request *http.Request) {
	rowLimit := min(s.exportMaxRows, defaultExportMaxRows)
	filter := findingFilterFromRequest(request, rowLimit)
	filter.Page = 1
	rows, total, err := s.repository.CurrentFindings(request.Context(), filter)
	if err != nil {
		s.internalError(response, err)
		return
	}
	exportRows := make([]currentFindingExportRow, 0, len(rows))
	for _, row := range rows {
		exportRows = append(exportRows, currentFindingJSON(row))
	}
	payload := currentFindingExport{
		ExportedAt: time.Now().UTC(),
		Total:      total,
		Exported:   len(exportRows),
		Truncated:  len(exportRows) < total,
		Filters:    currentFindingFilters(filter),
		Sort:       []string{"severity:desc", "customer:asc", "host:asc", "title:asc"},
		Findings:   exportRows,
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set(
		"Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "current-findings-"+time.Now().Format("20060102-150405")+".json"),
	)
	writer := &byteCapWriter{writer: response, remaining: s.exportMaxBytes}
	if err := json.NewEncoder(writer).Encode(payload); err != nil && !errors.Is(err, errExportByteLimit) {
		s.logger.Error("current findings export failed", "error", err)
	}
	if writer.capped {
		s.logger.Warn("current findings export cut off at byte limit", "limit", s.exportMaxBytes)
	}
}

func findingFilterFromRequest(request *http.Request, pageSize int) store.FindingQuery {
	query := request.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	return store.FindingQuery{
		CustomerID: query.Get("customer"),
		CID:        strings.TrimSpace(query.Get("cid")),
		Task:       strings.TrimSpace(query.Get("task")),
		Severity:   query.Get("severity"),
		Host:       strings.TrimSpace(query.Get("host")),
		Scope:      query.Get("scope"),
		Ticket:     query.Get("ticket"),
		Lifecycle:  query.Get("lifecycle"),
		Page:       max(page, 1),
		PageSize:   pageSize,
	}
}

func currentFindingFilters(filter store.FindingQuery) map[string]string {
	filters := make(map[string]string)
	for name, value := range map[string]string{
		"customer":  filter.CustomerID,
		"cid":       filter.CID,
		"task":      filter.Task,
		"severity":  filter.Severity,
		"host":      filter.Host,
		"scope":     filter.Scope,
		"ticket":    filter.Ticket,
		"lifecycle": filter.Lifecycle,
	} {
		if value != "" {
			filters[name] = value
		}
	}
	return filters
}

func currentFindingJSON(row store.CurrentFinding) currentFindingExportRow {
	return currentFindingExportRow{
		CustomerID: row.CustomerID, CustomerName: row.CustomerName, CID: row.CID,
		TaskID: row.TaskID, TaskName: row.TaskName, SnapshotID: row.SnapshotID,
		Fingerprint: row.Fingerprint, NVTOID: row.NVTOID, Title: row.Title,
		Host: row.Host, Port: row.Port, Location: row.Location,
		Severity: row.Severity, Threat: row.Threat, QOD: row.QOD,
		CVEs: row.CVEs, Remediation: row.Remediation,
		FirstSeen: row.FirstSeen, LastSeen: row.LastSeen, Lifecycle: row.Lifecycle,
		Disposition: row.Disposition, Justification: row.Justification,
		RemediationState: row.RemediationState, TicketState: row.TicketState,
	}
}

func (s *Server) findingStateUpdate(response http.ResponseWriter, request *http.Request) {
	state := request.PostForm.Get("state")
	switch state {
	case store.RemediationOpen, store.RemediationResolved, store.RemediationWontFix:
	default:
		http.Error(response, "invalid finding state", http.StatusBadRequest)
		return
	}
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if state != store.RemediationOpen && reason == "" {
		http.Error(response, "a reason is required", http.StatusBadRequest)
		return
	}
	annotation := store.FindingAnnotation{
		CustomerID:       strings.TrimSpace(request.PostForm.Get("customer_id")),
		TaskID:           strings.TrimSpace(request.PostForm.Get("task_id")),
		Fingerprint:      strings.TrimSpace(request.PostForm.Get("fingerprint")),
		Disposition:      store.DispositionActive,
		Justification:    reason,
		Operator:         "admin",
		RemediationState: state,
	}
	if annotation.CustomerID == "" || annotation.TaskID == "" || annotation.Fingerprint == "" {
		http.Error(response, "finding identity is required", http.StatusBadRequest)
		return
	}
	if err := s.repository.UpsertAnnotation(request.Context(), annotation); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(response, request)
			return
		}
		s.internalError(response, err)
		return
	}
	if err := s.repository.AddAuditEvent(request.Context(), store.AuditEvent{
		CustomerID:   annotation.CustomerID,
		Action:       "finding_" + state,
		ResourceKind: "finding",
		ResourceName: annotation.Fingerprint,
		Detail:       "task=" + annotation.TaskID + " reason=" + reason,
	}); err != nil {
		s.internalError(response, err)
		return
	}
	if s.hookwise != nil {
		s.hookwise.Trigger()
	}
	redirect := "/findings?notice=finding-state-saved"
	if state == store.RemediationOpen {
		redirect += "&scope=suppressed"
	}
	http.Redirect(response, request, redirect, http.StatusSeeOther)
}

func (s *Server) findingTicketRetry(response http.ResponseWriter, request *http.Request) {
	if s.hookwise == nil {
		http.Error(response, "ticket integration unavailable", http.StatusServiceUnavailable)
		return
	}
	customerID := strings.TrimSpace(request.PostForm.Get("customer_id"))
	taskID := strings.TrimSpace(request.PostForm.Get("task_id"))
	fingerprint := strings.TrimSpace(request.PostForm.Get("fingerprint"))
	if customerID == "" || taskID == "" || fingerprint == "" {
		http.Error(response, "finding identity is required", http.StatusBadRequest)
		return
	}
	if err := s.hookwise.RetryFinding(request.Context(), customerID, taskID, fingerprint); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(response, "finding ticket is not retryable", http.StatusConflict)
			return
		}
		s.internalError(response, err)
		return
	}
	http.Redirect(response, request, "/findings?notice=ticket-retry-requested", http.StatusSeeOther)
}

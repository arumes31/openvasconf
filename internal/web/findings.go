package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"openvasconf/internal/store"
)

func (s *Server) findingsList(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	filter := store.FindingQuery{
		CustomerID: query.Get("customer"),
		CID:        strings.TrimSpace(query.Get("cid")),
		Task:       strings.TrimSpace(query.Get("task")),
		Severity:   query.Get("severity"),
		Host:       strings.TrimSpace(query.Get("host")),
		Scope:      query.Get("scope"),
		Ticket:     query.Get("ticket"),
		Lifecycle:  query.Get("lifecycle"),
		Page:       max(page, 1),
		PageSize:   100,
	}
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

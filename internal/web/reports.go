package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openvasconf/internal/report"
	"openvasconf/internal/store"
)

// severityClass normalizes a GMP threat class to a CSS/severity key.
func severityClass(threat string) string {
	switch strings.ToLower(strings.ReplaceAll(threat, " ", "_")) {
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "false_positive":
		return "false_positive"
	default:
		return "log"
	}
}

// importStateClass maps a snapshot import state to an existing status chip
// class.
func importStateClass(state string) string {
	switch state {
	case store.ImportStateImported:
		return "applied"
	case store.ImportStateFailed:
		return "error"
	default:
		return "pending"
	}
}

func (s *Server) reportsList(response http.ResponseWriter, request *http.Request) {
	customerFilter := request.URL.Query().Get("customer")
	snapshots, err := s.repository.ListReportSnapshots(request.Context(), customerFilter, 200)
	if err != nil {
		s.internalError(response, err)
		return
	}
	customers, err := s.repository.Customers(request.Context(), false)
	if err != nil {
		s.internalError(response, err)
		return
	}
	s.render(response, request, "reports.html", pageData{
		Title:         "Reports",
		Authenticated: true,
		Reports:       snapshots,
		Customers:     customers,
		ReportFilter:  reportFilter{Customer: customerFilter},
		Notice:        noticeText(request.URL.Query().Get("notice")),
	})
}

func (s *Server) reportDetail(response http.ResponseWriter, request *http.Request) {
	snapshot, found := s.loadSnapshot(response, request)
	if !found {
		return
	}
	data, err := s.reportDetailData(request, snapshot, filterFromQuery(request))
	if err != nil {
		s.internalError(response, err)
		return
	}
	s.render(response, request, "report.html", data)
}

// loadSnapshot parses the {id} path value and loads the snapshot; it writes
// the 404/500 response and returns found=false on failure.
func (s *Server) loadSnapshot(
	response http.ResponseWriter,
	request *http.Request,
) (store.ReportSnapshot, bool) {
	id, err := strconv.ParseInt(request.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(response, request)
		return store.ReportSnapshot{}, false
	}
	snapshot, err := s.repository.ReportSnapshot(request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(response, request)
		return store.ReportSnapshot{}, false
	}
	if err != nil {
		s.internalError(response, err)
		return store.ReportSnapshot{}, false
	}
	return snapshot, true
}

func filterFromQuery(request *http.Request) reportFilter {
	query := request.URL.Query()
	return reportFilter{
		Severity:    query.Get("severity"),
		Host:        strings.TrimSpace(query.Get("host")),
		Port:        strings.TrimSpace(query.Get("port")),
		Lifecycle:   query.Get("lifecycle"),
		Disposition: query.Get("disposition"),
		Owner:       strings.TrimSpace(query.Get("owner")),
		Remediation: query.Get("remediation"),
		SLA:         query.Get("sla"),
	}
}

// reportDetailData assembles the full detail view: findings joined with
// lifecycle badges, effective annotations, SLA state, plus the trend history
// and the previous-snapshot link.
func (s *Server) reportDetailData(
	request *http.Request,
	snapshot store.ReportSnapshot,
	filter reportFilter,
) (pageData, error) {
	rows, previousID, trend, err := s.reportRows(request.Context(), snapshot)
	if err != nil {
		return pageData{}, err
	}
	data := pageData{
		Title:            "Report " + snapshot.TaskName,
		Authenticated:    true,
		Report:           &snapshot,
		ReportFilter:     filter,
		Notice:           noticeText(request.URL.Query().Get("notice")),
		PreviousReportID: previousID,
		Trend:            trend,
	}
	filtered := make([]findingView, 0, len(rows))
	for _, row := range rows {
		if matchesReportFilter(row, filter) {
			filtered = append(filtered, row)
		}
	}
	data.FindingRows = filtered
	return data, nil
}

// reportRows builds the unfiltered finding rows of a snapshot joined with
// lifecycle badges, effective annotations, and SLA state, plus the previous
// snapshot ID (0 when none) and the severity trend.
func (s *Server) reportRows(
	ctx context.Context,
	snapshot store.ReportSnapshot,
) ([]findingView, int64, []trendView, error) {
	findings, err := s.repository.ReportFindings(ctx, snapshot.ID)
	if err != nil {
		return nil, 0, nil, err
	}

	lifecycle := make(map[string]string, len(findings))
	annotations := map[string]store.FindingAnnotation{}
	firstSeen := map[string]time.Time{}
	settings, settingsErr := s.repository.Settings(ctx)
	var previousID int64
	var trend []trendView

	if snapshot.CustomerID != "" {
		previous, previousErr := s.repository.PreviousImportedSnapshot(ctx, snapshot)
		switch {
		case previousErr == nil:
			previousID = previous.ID
			previousFindings, findingsErr := s.repository.ReportFindings(ctx, previous.ID)
			if findingsErr != nil {
				return nil, 0, nil, findingsErr
			}
			lifecycle, _ = report.ClassifyFindings(previousFindings, findings)
		case errors.Is(previousErr, store.ErrNotFound):
			for _, finding := range findings {
				lifecycle[finding.Fingerprint] = report.LifecycleNew
			}
		default:
			return nil, 0, nil, previousErr
		}

		annotations, err = s.repository.AnnotationsForTask(ctx, snapshot.CustomerID, snapshot.TaskID)
		if err != nil {
			return nil, 0, nil, err
		}
		fingerprints := make([]string, 0, len(findings))
		for _, finding := range findings {
			fingerprints = append(fingerprints, finding.Fingerprint)
		}
		firstSeen, err = s.repository.FirstSeenForTask(ctx, snapshot.CustomerID, snapshot.TaskID, fingerprints)
		if err != nil {
			return nil, 0, nil, err
		}
		trendSnapshots, trendErr := s.repository.ReportTrend(ctx, snapshot.CustomerID, 12)
		if trendErr != nil {
			return nil, 0, nil, trendErr
		}
		trend = buildTrend(trendSnapshots)
	}

	now := time.Now()
	rows := make([]findingView, 0, len(findings))
	for _, finding := range findings {
		row := findingView{
			FindingSnapshot:  finding,
			Lifecycle:        lifecycle[finding.Fingerprint],
			Disposition:      store.DispositionActive,
			RemediationState: store.RemediationOpen,
			SLAState:         report.SLAStateNone,
		}
		annotation, annotated := annotations[finding.Fingerprint]
		if annotated {
			row.Disposition = report.EffectiveDisposition(annotation, now)
			row.Justification = annotation.Justification
			row.RemediationState = annotation.RemediationState
			row.RemediationOwner = annotation.RemediationOwner
			row.DueDate = annotation.DueDate
			row.ExpiresAt = annotation.ExpiresAt
		}
		if settingsErr == nil {
			var due *time.Time
			if annotated {
				due = annotation.DueDate
			}
			if deadline, ok := report.SLADeadline(
				finding.Severity,
				firstSeen[finding.Fingerprint],
				due,
				settings.SLA,
			); ok {
				row.SLADeadline = &deadline
				row.SLAState = report.SLAStateAt(deadline, now)
			}
		}
		rows = append(rows, row)
	}
	return rows, previousID, trend, nil
}

func buildTrend(snapshots []store.ReportSnapshot) []trendView {
	maxFindings := 0
	for _, snapshot := range snapshots {
		if snapshot.FindingCount > maxFindings {
			maxFindings = snapshot.FindingCount
		}
	}
	result := make([]trendView, 0, len(snapshots))
	for _, snapshot := range snapshots {
		point := trendView{Snapshot: snapshot}
		if maxFindings > 0 {
			point.TotalPct = snapshot.FindingCount * 100 / maxFindings
			point.HighPct = snapshot.CountHigh * 100 / maxFindings
		}
		result = append(result, point)
	}
	return result
}

func matchesReportFilter(row findingView, filter reportFilter) bool {
	if filter.Severity != "" && severityClass(row.Threat) != filter.Severity {
		return false
	}
	if filter.Host != "" && !strings.Contains(row.Host, filter.Host) {
		return false
	}
	if filter.Port != "" && !strings.Contains(row.Port, filter.Port) {
		return false
	}
	if filter.Lifecycle != "" && row.Lifecycle != filter.Lifecycle {
		return false
	}
	if filter.Disposition != "" && row.Disposition != filter.Disposition {
		return false
	}
	if filter.Owner != "" && !strings.Contains(row.RemediationOwner, filter.Owner) {
		return false
	}
	if filter.Remediation != "" && row.RemediationState != filter.Remediation {
		return false
	}
	if filter.SLA != "" && row.SLAState != filter.SLA {
		return false
	}
	return true
}

func (s *Server) reportAnnotate(response http.ResponseWriter, request *http.Request) {
	snapshot, found := s.loadSnapshot(response, request)
	if !found {
		return
	}
	ctx := request.Context()
	fail := func(err error) {
		data, dataErr := s.reportDetailData(request, snapshot, filterFromQuery(request))
		if dataErr != nil {
			s.internalError(response, dataErr)
			return
		}
		data.Error = err.Error()
		s.render(response, request, "report.html", data)
	}

	if snapshot.CustomerID == "" {
		fail(errors.New("cannot annotate findings of an unmapped report"))
		return
	}
	fingerprint := strings.TrimSpace(request.PostForm.Get("fingerprint"))
	findings, err := s.repository.ReportFindings(ctx, snapshot.ID)
	if err != nil {
		s.internalError(response, err)
		return
	}
	owns := false
	for _, finding := range findings {
		if finding.Fingerprint == fingerprint {
			owns = true
			break
		}
	}
	if !owns {
		fail(errors.New("the fingerprint does not belong to this report"))
		return
	}

	disposition := request.PostForm.Get("disposition")
	switch disposition {
	case store.DispositionActive, store.DispositionFalsePositive, store.DispositionAcceptedRisk:
	default:
		fail(fmt.Errorf("invalid disposition %q", disposition))
		return
	}
	justification := strings.TrimSpace(request.PostForm.Get("justification"))
	if disposition != store.DispositionActive && justification == "" {
		fail(errors.New("a justification is required for false positives and accepted risks"))
		return
	}
	remediationState := request.PostForm.Get("remediation_state")
	switch remediationState {
	case store.RemediationOpen, store.RemediationInProgress,
		store.RemediationResolved, store.RemediationWontFix:
	default:
		fail(fmt.Errorf("invalid remediation state %q", remediationState))
		return
	}
	dueDate, err := parseOptionalDate(request.PostForm.Get("due_date"), false)
	if err != nil {
		fail(errors.New("due date must use YYYY-MM-DD"))
		return
	}
	expiresAt, err := parseOptionalDate(request.PostForm.Get("expires_at"), true)
	if err != nil {
		fail(errors.New("expiry date must use YYYY-MM-DD"))
		return
	}
	if disposition != store.DispositionAcceptedRisk {
		expiresAt = nil
	}

	annotation := store.FindingAnnotation{
		CustomerID:       snapshot.CustomerID,
		TaskID:           snapshot.TaskID,
		Fingerprint:      fingerprint,
		Disposition:      disposition,
		Justification:    justification,
		Operator:         "admin",
		RemediationState: remediationState,
		RemediationOwner: strings.TrimSpace(request.PostForm.Get("remediation_owner")),
		DueDate:          dueDate,
		ExpiresAt:        expiresAt,
	}
	if err := s.repository.UpsertAnnotation(ctx, annotation); err != nil {
		s.internalError(response, err)
		return
	}
	if s.hookwise != nil {
		s.hookwise.Trigger()
	}
	http.Redirect(
		response,
		request,
		"/reports/"+strconv.FormatInt(snapshot.ID, 10)+"?notice=annotation-saved",
		http.StatusSeeOther,
	)
}

// parseOptionalDate parses an HTML date input. Empty input yields nil. With
// endOfDay the date covers the whole day (used for risk-acceptance expiry).
func parseOptionalDate(value string, endOfDay bool) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return nil, err
	}
	if endOfDay {
		parsed = parsed.Add(24*time.Hour - time.Second)
	}
	return &parsed, nil
}

func (s *Server) reportCompare(response http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	afterID, err := strconv.ParseInt(request.URL.Query().Get("b"), 10, 64)
	if err != nil {
		http.NotFound(response, request)
		return
	}
	after, err := s.repository.ReportSnapshot(ctx, afterID)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(response, request)
		return
	}
	if err != nil {
		s.internalError(response, err)
		return
	}

	// The "before" side defaults to the previous snapshot of the after side.
	beforeText := request.URL.Query().Get("a")
	var before store.ReportSnapshot
	if beforeText == "" {
		before, err = s.repository.PreviousImportedSnapshot(ctx, after)
	} else {
		var beforeID int64
		beforeID, err = strconv.ParseInt(beforeText, 10, 64)
		if err == nil {
			before, err = s.repository.ReportSnapshot(ctx, beforeID)
		}
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(response, request)
			return
		}
		s.internalError(response, err)
		return
	}
	if before.CustomerID == "" || before.CustomerID != after.CustomerID || before.TaskID != after.TaskID {
		http.Error(response, "reports belong to different customers or tasks", http.StatusForbidden)
		return
	}

	beforeFindings, err := s.repository.ReportFindings(ctx, before.ID)
	if err != nil {
		s.internalError(response, err)
		return
	}
	afterFindings, err := s.repository.ReportFindings(ctx, after.ID)
	if err != nil {
		s.internalError(response, err)
		return
	}
	lifecycle, resolved := report.ClassifyFindings(beforeFindings, afterFindings)
	comparison := &comparisonView{
		Before:   before,
		After:    after,
		Resolved: resolved,
	}
	for _, finding := range afterFindings {
		switch lifecycle[finding.Fingerprint] {
		case report.LifecycleNew:
			comparison.New = append(comparison.New, finding)
		case report.LifecycleRecurring:
			comparison.Recurring = append(comparison.Recurring, finding)
		}
	}
	s.render(response, request, "compare.html", pageData{
		Title:         "Compare reports",
		Authenticated: true,
		Compare:       comparison,
	})
}

func (s *Server) reportsRefresh(response http.ResponseWriter, request *http.Request) {
	if refresher, ok := s.reports.(interface{ Trigger() }); ok {
		refresher.Trigger()
	}
	http.Redirect(response, request, "/reports?notice=report-sync-requested", http.StatusSeeOther)
}

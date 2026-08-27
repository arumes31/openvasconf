package report

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
)

const (
	// maxImportAttempts caps how often one report is retried before it is
	// left for operator attention.
	maxImportAttempts = 5
	// initialRetryDelay is the base of the exponential retry backoff
	// (30s, 60s, 120s, ...) applied between import attempts of one report.
	initialRetryDelay = 30 * time.Second
	// maxDiagnosticLength caps sanitized failure diagnostics stored per
	// report; diagnostics never contain raw report XML or credentials.
	maxDiagnosticLength = 500
	// healthLink points the health strip at the report list.
	healthLink = "/reports"
)

// Store is the narrow repository facade the syncer needs.
type Store interface {
	ReportImportState(ctx context.Context, reportID string) (string, error)
	SaveReportSnapshot(
		ctx context.Context,
		snapshot store.ReportSnapshot,
		findings []store.FindingSnapshot,
	) error
	RecordReportImportFailure(
		ctx context.Context,
		reportID, taskID, taskName, customerID, diagnostic string,
	) error
	DeleteFailedReportImport(ctx context.Context, reportID string) error
	ResetFailedReportImports(ctx context.Context) error
	PendingReportRetries(ctx context.Context, maxAttempts int) ([]store.ReportSnapshot, error)
	CustomerForManagedTask(ctx context.Context, gvmTaskID string) (string, error)
	ReportImportStats(ctx context.Context) (store.ReportImportStats, error)
}

// Greenbone is the narrow GMP facade the syncer needs.
type Greenbone interface {
	Tasks(ctx context.Context) ([]gmp.TaskStatus, error)
	Report(ctx context.Context, reportID string, limits gmp.ReportLimits) (gmp.ReportDetails, error)
}

// Limits bounds report imports.
type Limits struct {
	MaxFindings int
	MaxXMLBytes int64
	Concurrency int
}

// Syncer periodically discovers completed Greenbone reports of managed tasks
// and imports them as normalized snapshots. It is independent of the
// reconciler so report failures cannot block customer configuration.
type Syncer struct {
	store     Store
	greenbone Greenbone
	logger    *slog.Logger
	interval  time.Duration
	limits    Limits
	trigger   chan struct{}

	runMu     sync.Mutex
	healthMu  sync.Mutex
	cycleRan  bool
	lastCycle time.Time
	lastErr   error
	nextRetry map[string]time.Time
	failures  map[string]int
}

// NewSyncer constructs the report synchronization service.
func NewSyncer(
	repository Store,
	greenbone Greenbone,
	logger *slog.Logger,
	interval time.Duration,
	limits Limits,
) *Syncer {
	if limits.Concurrency < 1 {
		limits.Concurrency = 1
	}
	if limits.MaxFindings <= 0 {
		limits.MaxFindings = 50000
	}
	if limits.MaxXMLBytes <= 0 {
		limits.MaxXMLBytes = 64 << 20
	}
	return &Syncer{
		store:     repository,
		greenbone: greenbone,
		logger:    logger,
		interval:  interval,
		limits:    limits,
		trigger:   make(chan struct{}, 1),
		nextRetry: make(map[string]time.Time),
		failures:  make(map[string]int),
	}
}

// Trigger requests an out-of-band synchronization cycle and rearms failed
// imports, for example when the operator selects Refresh reports. It never
// blocks.
func (s *Syncer) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Run executes one cycle immediately and then one per interval or trigger
// until the context is canceled.
func (s *Syncer) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.runAndLog(ctx, false)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runAndLog(ctx, false)
		case <-s.trigger:
			s.runAndLog(ctx, true)
		}
	}
}

func (s *Syncer) runAndLog(ctx context.Context, retryExhausted bool) {
	if err := s.syncOnce(ctx, retryExhausted); err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Error("report synchronization failed", "error", err)
	}
}

// SyncOnce executes one discovery and import cycle.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	return s.syncOnce(ctx, false)
}

func (s *Syncer) syncOnce(ctx context.Context, retryExhausted bool) error {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	var err error
	if retryExhausted {
		err = s.store.ResetFailedReportImports(ctx)
		if err != nil {
			err = fmt.Errorf("report: resetting failed imports: %w", err)
		} else {
			s.clearAllRetries()
		}
	}
	if err == nil {
		err = s.syncLocked(ctx)
	}
	s.healthMu.Lock()
	s.cycleRan = true
	s.lastCycle = time.Now()
	s.lastErr = err
	s.healthMu.Unlock()
	return err
}

func (s *Syncer) clearAllRetries() {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	clear(s.nextRetry)
	clear(s.failures)
}

func (s *Syncer) syncLocked(ctx context.Context) error {
	jobs, err := s.discover(ctx)
	if err != nil {
		return err
	}

	sem := make(chan struct{}, s.limits.Concurrency)
	var wg sync.WaitGroup
	var abortMu sync.Mutex
	var aborted bool
	failed := 0
	for _, job := range jobs {
		abortMu.Lock()
		stop := aborted
		abortMu.Unlock()
		if stop || ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			importErr := s.importOne(ctx, job)
			switch {
			case importErr == nil:
			case isAuthFailure(importErr):
				// Authentication failures stop the whole cycle: hammering
				// gvmd with doomed requests helps nobody.
				abortMu.Lock()
				aborted = true
				err = importErr
				abortMu.Unlock()
			default:
				abortMu.Lock()
				failed++
				abortMu.Unlock()
				s.logger.Warn(
					"report import failed",
					"report_id", job.reportID,
					"error", importErr,
				)
			}
		}()
	}
	wg.Wait()
	if err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("report: %d report import(s) failed this cycle", failed)
	}
	return nil
}

type importJob struct {
	reportID   string
	taskID     string
	taskName   string
	customerID string
	retry      bool
}

// discover collects reports that still need importing: new last reports of
// managed tasks, plus previously failed imports that are due for a retry.
func (s *Syncer) discover(ctx context.Context) ([]importJob, error) {
	tasks, err := s.greenbone.Tasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("report: discovering tasks: %w", err)
	}

	jobs := make([]importJob, 0)
	seen := make(map[string]struct{})
	for _, task := range tasks {
		lastReport := task.LastReport
		if lastReport == nil || lastReport.ID == "" || !importableStatus(lastReport.Status) {
			continue
		}
		_, stateErr := s.store.ReportImportState(ctx, lastReport.ID)
		switch {
		case stateErr == nil:
			// Already imported or tracked as failed; failures are retried
			// through PendingReportRetries below.
			continue
		case !errors.Is(stateErr, store.ErrNotFound):
			return nil, fmt.Errorf("report: checking import state: %w", stateErr)
		}
		customerID, mapErr := s.store.CustomerForManagedTask(ctx, task.ID)
		if errors.Is(mapErr, store.ErrNotFound) {
			continue
		}
		if mapErr != nil {
			return nil, fmt.Errorf("report: mapping task to customer: %w", mapErr)
		}
		jobs = append(jobs, importJob{
			reportID:   lastReport.ID,
			taskID:     task.ID,
			taskName:   task.Name,
			customerID: customerID,
		})
		seen[lastReport.ID] = struct{}{}
	}

	retries, err := s.store.PendingReportRetries(ctx, maxImportAttempts)
	if err != nil {
		return nil, fmt.Errorf("report: querying pending retries: %w", err)
	}
	for _, retry := range retries {
		if _, duplicate := seen[retry.ReportID]; duplicate {
			continue
		}
		if !s.retryDue(retry.ReportID) {
			continue
		}
		jobs = append(jobs, importJob{
			reportID:   retry.ReportID,
			taskID:     retry.TaskID,
			taskName:   retry.TaskName,
			customerID: retry.CustomerID,
			retry:      true,
		})
		seen[retry.ReportID] = struct{}{}
	}
	return jobs, nil
}

// importableStatus treats every report status that is not an active scan
// state as importable (Done, Stopped, Interrupted, ...).
func importableStatus(status string) bool {
	switch strings.ToLower(status) {
	case "running", "requested", "queued", "processing":
		return false
	}
	return true
}

func (s *Syncer) importOne(ctx context.Context, job importJob) error {
	details, err := s.greenbone.Report(ctx, job.reportID, gmp.ReportLimits{
		MaxBytes:   s.limits.MaxXMLBytes,
		MaxResults: s.limits.MaxFindings,
	})
	if err != nil {
		if isAuthFailure(err) {
			return err
		}
		if job.retry && isMissingReport(err) {
			if deleteErr := s.store.DeleteFailedReportImport(ctx, job.reportID); deleteErr != nil {
				return errors.Join(err, deleteErr)
			}
			s.clearRetry(job.reportID)
			s.logger.Info("stale report import removed", "report_id", job.reportID)
			return nil
		}
		diagnostic := sanitizeDiagnostic(err)
		if recordErr := s.store.RecordReportImportFailure(
			ctx,
			job.reportID,
			job.taskID,
			job.taskName,
			job.customerID,
			diagnostic,
		); recordErr != nil {
			return errors.Join(err, recordErr)
		}
		s.scheduleRetry(job.reportID)
		return err
	}

	snapshot, findings := Normalize(job.customerID, details)
	if snapshot.ReportID == "" {
		snapshot.ReportID = job.reportID
	}
	if err := s.store.SaveReportSnapshot(ctx, snapshot, findings); err != nil {
		return fmt.Errorf("report: saving snapshot: %w", err)
	}
	s.clearRetry(job.reportID)
	s.logger.Info(
		"report snapshot imported",
		"report_id", snapshot.ReportID,
		"customer_id", job.customerID,
		"findings", len(findings),
	)
	return nil
}

// scheduleRetry applies exponential backoff (30s, 60s, 120s, ...) per report
// between import attempts. The store-level attempt counter independently caps
// the total number of attempts.
func (s *Syncer) scheduleRetry(reportID string) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	s.failures[reportID]++
	shift := s.failures[reportID] - 1
	if shift > 4 {
		shift = 4
	}
	s.nextRetry[reportID] = time.Now().Add(initialRetryDelay << shift)
}

func (s *Syncer) clearRetry(reportID string) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	delete(s.nextRetry, reportID)
	delete(s.failures, reportID)
}

func (s *Syncer) retryDue(reportID string) bool {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	due, scheduled := s.nextRetry[reportID]
	return !scheduled || !time.Now().Before(due)
}

// isAuthFailure reports whether the error is a GMP authentication failure
// (protocol status 4xx on the authenticate command).
func isAuthFailure(err error) bool {
	var protocolError *gmp.ProtocolError
	if errors.As(err, &protocolError) {
		return protocolError.Command == "authenticate" &&
			strings.HasPrefix(protocolError.Status, "4")
	}
	return false
}

func isMissingReport(err error) bool {
	var protocolError *gmp.ProtocolError
	return errors.As(err, &protocolError) &&
		protocolError.Command == "get_reports" &&
		protocolError.Status == "404"
}

// sanitizeDiagnostic reduces a failure to a bounded single-line message. GMP
// errors never carry credentials or report payloads; the cap and whitespace
// folding keep stored diagnostics small and safe to display.
func sanitizeDiagnostic(err error) string {
	text := strings.Join(strings.Fields(err.Error()), " ")
	runes := []rune(text)
	if len(runes) > maxDiagnosticLength {
		return string(runes[:maxDiagnosticLength])
	}
	return text
}

// ReportHealth implements the health-strip component for report
// synchronization.
func (s *Syncer) ReportHealth(
	ctx context.Context,
) (state, detail, guidance, link string) {
	s.healthMu.Lock()
	ran, lastCycle, lastErr := s.cycleRan, s.lastCycle, s.lastErr
	s.healthMu.Unlock()

	if !ran {
		return "unknown", "report synchronization has not run yet", "", healthLink
	}
	if lastErr != nil {
		return "degraded",
			"last report synchronization cycle failed",
			"Check the Greenbone connection and the service logs.",
			healthLink
	}
	if time.Since(lastCycle) > 3*s.interval {
		return "degraded",
			"report synchronization is stale",
			"Check whether the service is busy or stuck; trigger a refresh from the reports page.",
			healthLink
	}
	stats, err := s.store.ReportImportStats(ctx)
	if err != nil {
		return "degraded",
			"report import statistics unavailable",
			"Check the service logs for repository errors.",
			healthLink
	}
	if stats.FailedCount > 0 {
		return "degraded",
			fmt.Sprintf("%d report import(s) failed", stats.FailedCount),
			"Inspect the failed imports, then use Refresh reports to retry them.",
			healthLink
	}
	detail = "reports up to date"
	if stats.LastImportedAt != nil {
		detail = fmt.Sprintf(
			"%d report(s) imported, last at %s",
			stats.ImportedCount,
			stats.LastImportedAt.Format("2006-01-02 15:04"),
		)
	}
	return "ok", detail, "", healthLink
}

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
)

type progressTracker struct {
	repository  Repository
	runID       int64
	customerID  string
	attempt     int
	maxAttempts int
	total       int
	completed   int
	phase       string
	current     string
}

func (p *progressTracker) setTotal(ctx context.Context, total int) {
	p.total = total
	p.phase = "applying desired state"
	p.update(ctx, "", "", nil)
}

func (p *progressTracker) begin(ctx context.Context, action, kind, name string) time.Time {
	if p.total <= p.completed {
		p.total = p.completed + 1
	}
	p.current = fmt.Sprintf("%s %s %s", action, kind, name)
	p.update(ctx, "", "", nil)
	return time.Now()
}

func (p *progressTracker) finish(
	ctx context.Context,
	started time.Time,
	action,
	kind,
	name string,
	operationErr error,
) {
	p.completed++
	p.current = ""
	status := "succeeded"
	detail := ""
	if operationErr != nil {
		status = "failed"
		detail = operationErr.Error()
	}
	_ = p.repository.AddReconcileOperation(ctx, store.ReconcileOperation{
		RunID: p.runID, CustomerID: p.customerID, Action: action,
		ResourceKind: kind, ResourceName: name, Status: status,
		Detail: detail, Duration: time.Since(started),
	})
	p.update(ctx, "", "", nil)
}

func (p *progressTracker) fail(ctx context.Context, runErr error) {
	if runErr == nil {
		p.phase = "complete"
		p.current = ""
		p.update(ctx, "", "", nil)
		return
	}
	p.phase = "failed"
	safe := safeReconcileError(runErr)
	var nextRetry *time.Time
	if isTransient(runErr) && p.attempt < p.maxAttempts {
		next := time.Now().Add(initialRetryBackoff * time.Duration(1<<(p.attempt-1)))
		nextRetry = &next
		p.phase = "waiting for automatic retry"
	}
	p.update(ctx, safe, runErr.Error(), nextRetry)
}

func (p *progressTracker) update(
	ctx context.Context,
	safeError,
	technicalError string,
	nextRetry *time.Time,
) {
	_ = p.repository.UpdateReconcileProgress(ctx, p.runID, p.customerID, store.ReconcileProgress{
		Phase: p.phase, CurrentOperation: p.current,
		CompletedOperations: p.completed, TotalOperations: p.total,
		Attempt: p.attempt, MaxAttempts: p.maxAttempts, NextRetryAt: nextRetry,
		SafeError: safeError, TechnicalError: technicalError,
	})
}

func safeReconcileError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrOwnershipMismatch):
		return "A Greenbone object no longer has this installation's ownership marker. No unsafe change was made."
	case errors.Is(err, context.DeadlineExceeded):
		return "Greenbone did not respond before the operation timeout."
	case errors.Is(err, context.Canceled):
		return "Reconciliation was canceled before it completed."
	}
	var protocolError *gmp.ProtocolError
	if errors.As(err, &protocolError) {
		if strings.HasPrefix(protocolError.Status, "5") {
			return "Greenbone is temporarily unavailable; automatic retry will be attempted."
		}
		return "Greenbone rejected a desired-state operation. Review the selected scanner, configuration, and port list."
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return "The GMP connection failed; automatic retry will be attempted."
	}
	return "Reconciliation could not apply the complete desired state. Open technical details or history for diagnostics."
}

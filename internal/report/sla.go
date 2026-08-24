package report

import (
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/store"
)

// SLA states of a finding.
const (
	// SLAStateNone marks findings without an SLA (severity 0 / log).
	SLAStateNone = "none"
	// SLAStateOnTrack marks findings with comfortable time left.
	SLAStateOnTrack = "on_track"
	// SLAStateDueSoon marks findings whose deadline is near.
	SLAStateDueSoon = "due_soon"
	// SLAStateOverdue marks findings past their deadline.
	SLAStateOverdue = "overdue"
)

// dueSoonThreshold is the remaining time below which a finding counts as
// due soon. The rule is a fixed 48 hours before the deadline (chosen over a
// relative 25% window so short and long SLAs behave predictably).
const dueSoonThreshold = 48 * time.Hour

// slaBandDays maps a severity score to the policy duration of its band.
// Critical starts at 9.0, high at 7.0, medium at 4.0, low above 0;
// severity 0 (log) carries no SLA.
func slaBandDays(severity float64, policy customer.SLAPolicy) (days int, ok bool) {
	switch {
	case severity >= 9.0:
		return policy.CriticalDays, true
	case severity >= 7.0:
		return policy.HighDays, true
	case severity >= 4.0:
		return policy.MediumDays, true
	case severity > 0:
		return policy.LowDays, true
	}
	return 0, false
}

// SLADeadline computes the remediation deadline of a finding: first seen plus
// the band duration. An operator-set due date wins only when it is earlier
// than the policy deadline; a later operator date never extends the SLA.
func SLADeadline(
	severity float64,
	firstSeen time.Time,
	operatorDue *time.Time,
	policy customer.SLAPolicy,
) (time.Time, bool) {
	days, ok := slaBandDays(severity, policy)
	if !ok || firstSeen.IsZero() {
		return time.Time{}, false
	}
	deadline := firstSeen.AddDate(0, 0, days)
	if operatorDue != nil && operatorDue.Before(deadline) {
		deadline = *operatorDue
	}
	return deadline, true
}

// SLAStateAt classifies a deadline relative to now: overdue past the
// deadline, due soon within dueSoonThreshold of it, otherwise on track.
func SLAStateAt(deadline time.Time, now time.Time) string {
	if !now.Before(deadline) {
		return SLAStateOverdue
	}
	if deadline.Sub(now) <= dueSoonThreshold {
		return SLAStateDueSoon
	}
	return SLAStateOnTrack
}

// EffectiveDisposition computes the current disposition of an annotation.
// Any disposition with an expiry in the past reads as active again; the
// stored history row is never rewritten.
func EffectiveDisposition(annotation store.FindingAnnotation, now time.Time) string {
	if annotation.Disposition != store.DispositionActive &&
		annotation.ExpiresAt != nil &&
		!annotation.ExpiresAt.After(now) {
		return store.DispositionActive
	}
	if annotation.Disposition == "" {
		return store.DispositionActive
	}
	return annotation.Disposition
}

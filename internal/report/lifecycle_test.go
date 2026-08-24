package report

import (
	"testing"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/store"
)

func TestClassifyNewRecurringResolved(t *testing.T) {
	t.Parallel()

	older := []string{"v1:a", "v1:b", "v1:c"}
	newer := []string{"v1:b", "v1:c", "v1:d"}
	lifecycle := Classify(older, newer)

	if lifecycle["v1:d"] != LifecycleNew {
		t.Errorf("v1:d = %q, want new", lifecycle["v1:d"])
	}
	if lifecycle["v1:b"] != LifecycleRecurring || lifecycle["v1:c"] != LifecycleRecurring {
		t.Errorf("recurring = %q/%q", lifecycle["v1:b"], lifecycle["v1:c"])
	}
	if lifecycle["v1:a"] != LifecycleResolved {
		t.Errorf("v1:a = %q, want resolved", lifecycle["v1:a"])
	}
}

func TestClassifyFirstSnapshotIsAllNew(t *testing.T) {
	t.Parallel()

	lifecycle := Classify(nil, []string{"v1:a", "v1:b"})
	for _, fingerprint := range []string{"v1:a", "v1:b"} {
		if lifecycle[fingerprint] != LifecycleNew {
			t.Errorf("%s = %q, want new", fingerprint, lifecycle[fingerprint])
		}
	}
}

func TestClassifyFindingsResolvedRows(t *testing.T) {
	t.Parallel()

	older := []store.FindingSnapshot{
		{Fingerprint: "v1:gone", Title: "old finding"},
		{Fingerprint: "v1:stay", Title: "still here"},
	}
	newer := []store.FindingSnapshot{{Fingerprint: "v1:stay", Title: "still here"}}
	lifecycle, resolved := ClassifyFindings(older, newer)

	if lifecycle["v1:stay"] != LifecycleRecurring || lifecycle["v1:gone"] != LifecycleResolved {
		t.Fatalf("lifecycle = %#v", lifecycle)
	}
	if len(resolved) != 1 || resolved[0].Fingerprint != "v1:gone" {
		t.Errorf("resolved = %#v", resolved)
	}
}

func TestEffectiveDispositionExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	annotation := store.FindingAnnotation{
		Disposition: store.DispositionAcceptedRisk,
		ExpiresAt:   &expired,
	}
	if got := EffectiveDisposition(annotation, now); got != store.DispositionActive {
		t.Errorf("expired disposition = %q, want active", got)
	}

	annotation.ExpiresAt = &future
	if got := EffectiveDisposition(annotation, now); got != store.DispositionAcceptedRisk {
		t.Errorf("unexpired disposition = %q, want accepted_risk", got)
	}

	annotation = store.FindingAnnotation{Disposition: store.DispositionFalsePositive}
	if got := EffectiveDisposition(annotation, now); got != store.DispositionFalsePositive {
		t.Errorf("disposition without expiry = %q", got)
	}

	if got := EffectiveDisposition(store.FindingAnnotation{}, now); got != store.DispositionActive {
		t.Errorf("zero annotation disposition = %q, want active", got)
	}
}

func TestSLADeadlineBands(t *testing.T) {
	t.Parallel()

	policy := customer.SLAPolicy{CriticalDays: 7, HighDays: 14, MediumDays: 30, LowDays: 90}
	firstSeen := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		severity float64
		wantDay  int // day of month of the expected deadline
		ok       bool
	}{
		{9.8, 8, true},
		{9.0, 8, true},
		{7.5, 15, true},
		{4.0, 31, true},
		{0.1, 30, true}, // low band: 2026-08-01 + 90 days = 2026-10-30; checked below
		{0.0, 0, false},
	}
	for _, testCase := range cases {
		deadline, ok := SLADeadline(testCase.severity, firstSeen, nil, policy)
		if ok != testCase.ok {
			t.Errorf("severity %v ok = %t, want %t", testCase.severity, ok, testCase.ok)
			continue
		}
		if !ok {
			continue
		}
		expected := firstSeen.AddDate(0, 0, map[float64]int{9.8: 7, 9.0: 7, 7.5: 14, 4.0: 30, 0.1: 90}[testCase.severity])
		if !deadline.Equal(expected) {
			t.Errorf("severity %v deadline = %v, want %v", testCase.severity, deadline, expected)
		}
	}
}

func TestSLADeadlineOperatorOverride(t *testing.T) {
	t.Parallel()

	policy := customer.SLAPolicy{CriticalDays: 7, HighDays: 14, MediumDays: 30, LowDays: 90}
	firstSeen := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	earlier := firstSeen.AddDate(0, 0, 3)
	deadline, ok := SLADeadline(9.8, firstSeen, &earlier, policy)
	if !ok || !deadline.Equal(earlier) {
		t.Errorf("earlier operator due date = %v, %t; want %v", deadline, ok, earlier)
	}

	later := firstSeen.AddDate(0, 0, 60)
	deadline, _ = SLADeadline(9.8, firstSeen, &later, policy)
	if want := firstSeen.AddDate(0, 0, 7); !deadline.Equal(want) {
		t.Errorf("later operator due date = %v, want policy deadline %v", deadline, want)
	}

	if _, ok := SLADeadline(9.8, time.Time{}, nil, policy); ok {
		t.Error("missing first-seen must disable the SLA")
	}
}

func TestSLAStateAt(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	if got := SLAStateAt(now.Add(-time.Hour), now); got != SLAStateOverdue {
		t.Errorf("past deadline = %q, want overdue", got)
	}
	if got := SLAStateAt(now, now); got != SLAStateOverdue {
		t.Errorf("exact deadline = %q, want overdue", got)
	}
	if got := SLAStateAt(now.Add(24*time.Hour), now); got != SLAStateDueSoon {
		t.Errorf("deadline in 24h = %q, want due_soon", got)
	}
	if got := SLAStateAt(now.Add(48*time.Hour), now); got != SLAStateDueSoon {
		t.Errorf("deadline in 48h = %q, want due_soon", got)
	}
	if got := SLAStateAt(now.Add(72*time.Hour), now); got != SLAStateOnTrack {
		t.Errorf("deadline in 72h = %q, want on_track", got)
	}
}

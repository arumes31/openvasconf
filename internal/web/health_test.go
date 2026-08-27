package web

import (
	"strings"
	"testing"
	"time"

	"openvasconf/internal/gmp"
)

func TestSummarizeFeedsAtAppliesSLA(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		age   time.Duration
		state string
	}{
		{name: "green through five days", age: 5 * 24 * time.Hour, state: "ok"},
		{name: "yellow after five days", age: 6 * 24 * time.Hour, state: "warning"},
		{name: "yellow through eight days", age: 8 * 24 * time.Hour, state: "warning"},
		{name: "red after eight days", age: 9 * 24 * time.Hour, state: "critical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			component := summarizeFeedsAt([]gmp.Feed{{
				Name: "NVT", UpdatedAt: now.Add(-test.age),
			}}, now)
			if component.State != test.state {
				t.Errorf("state = %q, want %q", component.State, test.state)
			}
			if !strings.Contains(component.Detail, "2026-") {
				t.Errorf("detail %q does not include oldest feed timestamp", component.Detail)
			}
		})
	}
}

func TestSummarizeFeedsAtReportsMissingTimestamps(t *testing.T) {
	t.Parallel()
	component := summarizeFeedsAt([]gmp.Feed{{Name: "NVT"}}, time.Now())
	if component.State != "warning" || component.Detail != "feed timestamps unavailable" {
		t.Fatalf("component = %#v", component)
	}
}

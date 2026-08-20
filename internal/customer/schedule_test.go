package customer

import (
	"bytes"
	"testing"
	"time"
)

func TestRandomSchedule(t *testing.T) {
	t.Parallel()

	weekday, minute, err := RandomSchedule(bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("RandomSchedule() error = %v", err)
	}
	if weekday < Monday || weekday > Thursday {
		t.Errorf("weekday = %d, want Monday through Thursday", weekday)
	}
	if minute < EarliestMinute || minute > LatestMinute {
		t.Errorf("minute = %d, want %d through %d", minute, EarliestMinute, LatestMinute)
	}
}

func TestWeekdayName(t *testing.T) {
	t.Parallel()

	if got := WeekdayName(3); got != "Wednesday" {
		t.Errorf("WeekdayName(3) = %q, want Wednesday", got)
	}
}

func TestNextScheduleUsesCustomerTimezoneAcrossDST(t *testing.T) {
	t.Parallel()
	value := Customer{ScheduleWeekday: Monday, ScheduleMinute: 8 * 60, Timezone: "Europe/Vienna"}
	after := time.Date(2026, time.March, 27, 12, 0, 0, 0, time.UTC)
	next, err := value.NextSchedule(after)
	if err != nil {
		t.Fatal(err)
	}
	if got := next.Format("2006-01-02 15:04 -0700"); got != "2026-03-30 08:00 +0200" {
		t.Fatalf("next schedule = %s", got)
	}
}

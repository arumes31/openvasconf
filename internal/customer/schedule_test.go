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
	if weekday < Monday || weekday > Sunday {
		t.Errorf("weekday = %d, want Monday through Sunday", weekday)
	}
	if minute < EarliestMinute || minute > LatestMinute {
		t.Errorf("minute = %d, want %d through %d", minute, EarliestMinute, LatestMinute)
	}
}

func TestValidateSchedulePolicy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		policy SchedulePolicy
		valid  bool
	}{
		{"all weekdays full day", SchedulePolicy{Weekdays: []int{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1439}, true},
		{"weekend night window", SchedulePolicy{Weekdays: []int{6, 7}, StartMinute: 22 * 60, EndMinute: 23*60 + 59}, true},
		{"same start and end", SchedulePolicy{Weekdays: []int{3}, StartMinute: 300, EndMinute: 300}, true},
		{"no weekdays", SchedulePolicy{Weekdays: nil, StartMinute: 0, EndMinute: 60}, false},
		{"weekday out of range", SchedulePolicy{Weekdays: []int{8}, StartMinute: 0, EndMinute: 60}, false},
		{"duplicate weekday", SchedulePolicy{Weekdays: []int{2, 2}, StartMinute: 0, EndMinute: 60}, false},
		{"end before start", SchedulePolicy{Weekdays: []int{1}, StartMinute: 600, EndMinute: 300}, false},
		{"negative start", SchedulePolicy{Weekdays: []int{1}, StartMinute: -1, EndMinute: 60}, false},
		{"end past day", SchedulePolicy{Weekdays: []int{1}, StartMinute: 0, EndMinute: 1440}, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSchedulePolicy(testCase.policy)
			if testCase.valid && err != nil {
				t.Errorf("ValidateSchedulePolicy() error = %v, want valid", err)
			}
			if !testCase.valid && err == nil {
				t.Error("ValidateSchedulePolicy() = nil, want error")
			}
		})
	}
}

func TestParseWeekdaysAcceptsFullWeek(t *testing.T) {
	t.Parallel()

	weekdays, err := ParseWeekdays("5,6,7")
	if err != nil {
		t.Fatalf("ParseWeekdays() error = %v", err)
	}
	if len(weekdays) != 3 || weekdays[0] != 5 || weekdays[2] != 7 {
		t.Errorf("ParseWeekdays() = %v", weekdays)
	}
	if _, err := ParseWeekdays("0"); err == nil {
		t.Error("ParseWeekdays(0) = nil, want error")
	}
}

func TestWeekdayName(t *testing.T) {
	t.Parallel()

	if got := WeekdayName(3); got != "Wednesday" {
		t.Errorf("WeekdayName(3) = %q, want Wednesday", got)
	}
	if got := WeekdayName(7); got != "Sunday" {
		t.Errorf("WeekdayName(7) = %q, want Sunday", got)
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

func TestNextScheduleSundayEvening(t *testing.T) {
	t.Parallel()
	value := Customer{ScheduleWeekday: Sunday, ScheduleMinute: 23*60 + 30, Timezone: "UTC"}
	after := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC) // a Saturday
	next, err := value.NextSchedule(after)
	if err != nil {
		t.Fatal(err)
	}
	if got := next.Format("2006-01-02 15:04"); got != "2026-08-23 23:30" {
		t.Fatalf("next schedule = %s", got)
	}
}

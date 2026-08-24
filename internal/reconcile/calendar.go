package reconcile

import (
	"fmt"
	"strings"
	"time"

	"openvasconf/internal/customer"
)

func weeklyCalendar(value customer.Customer) string {
	weekdayCodes := map[int]string{
		1: "MO",
		2: "TU",
		3: "WE",
		4: "TH",
		5: "FR",
		6: "SA",
		7: "SU",
	}
	base := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	date := base.AddDate(0, 0, value.ScheduleWeekday-1)
	hour := value.ScheduleMinute / 60
	minute := value.ScheduleMinute % 60
	start := time.Date(date.Year(), date.Month(), date.Day(), hour, minute, 0, 0, time.UTC)
	lines := []string{
		"BEGIN:VCALENDAR",
		"VERSION:2.0",
		"PRODID:-//openvasconf//weekly customer scan//EN",
		"BEGIN:VEVENT",
		"UID:" + value.ID + "@openvasconf",
		"DTSTAMP:20240101T000000Z",
		"DTSTART:" + start.Format("20060102T150405"),
		fmt.Sprintf("RRULE:FREQ=WEEKLY;BYDAY=%s", weekdayCodes[value.ScheduleWeekday]),
		"SUMMARY:" + escapeICalendar(value.Name) + " vulnerability scan",
		"END:VEVENT",
		"END:VCALENDAR",
		"",
	}
	return strings.Join(lines, "\r\n")
}

func escapeICalendar(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, ";", "\\;")
	value = strings.ReplaceAll(value, ",", "\\,")
	value = strings.ReplaceAll(value, "\r", "")
	return strings.ReplaceAll(value, "\n", "\\n")
}

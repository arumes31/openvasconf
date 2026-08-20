package customer

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
)

const (
	Monday         = 1
	Thursday       = 4
	EarliestMinute = 7 * 60
	LatestMinute   = 15 * 60
)

func RandomSchedule(random io.Reader) (weekday, minute int, err error) {
	return RandomScheduleWithPolicy(random, SchedulePolicy{
		Weekdays:    []int{Monday, 2, 3, Thursday},
		StartMinute: EarliestMinute,
		EndMinute:   LatestMinute,
	})
}

func RandomScheduleWithPolicy(
	random io.Reader,
	policy SchedulePolicy,
) (weekday, minute int, err error) {
	if random == nil {
		random = rand.Reader
	}
	if err := ValidateSchedulePolicy(policy); err != nil {
		return 0, 0, err
	}

	dayValue, err := rand.Int(random, big.NewInt(int64(len(policy.Weekdays))))
	if err != nil {
		return 0, 0, fmt.Errorf("generating schedule weekday: %w", err)
	}
	minuteCount := policy.EndMinute - policy.StartMinute + 1
	minuteValue, err := rand.Int(random, big.NewInt(int64(minuteCount)))
	if err != nil {
		return 0, 0, fmt.Errorf("generating schedule time: %w", err)
	}
	return policy.Weekdays[dayValue.Int64()], policy.StartMinute + int(minuteValue.Int64()), nil
}

func ValidateSchedulePolicy(policy SchedulePolicy) error {
	if len(policy.Weekdays) == 0 || len(policy.Weekdays) > Thursday-Monday+1 {
		return errors.New("customer: select at least one allowed weekday")
	}
	seen := make(map[int]struct{}, len(policy.Weekdays))
	for _, weekday := range policy.Weekdays {
		if weekday < Monday || weekday > Thursday {
			return fmt.Errorf("customer: weekday %d is outside Monday through Thursday", weekday)
		}
		if _, duplicate := seen[weekday]; duplicate {
			return fmt.Errorf("customer: weekday %d is duplicated", weekday)
		}
		seen[weekday] = struct{}{}
	}
	if policy.StartMinute < EarliestMinute || policy.EndMinute > LatestMinute ||
		policy.StartMinute > policy.EndMinute {
		return fmt.Errorf(
			"customer: schedule window must remain between %s and %s",
			MinuteTime(EarliestMinute),
			MinuteTime(LatestMinute),
		)
	}
	return nil
}

func ParseWeekdays(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	result := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		weekday := 0
		if _, err := fmt.Sscanf(part, "%d", &weekday); err != nil {
			return nil, fmt.Errorf("customer: parsing weekday %q: %w", part, err)
		}
		result = append(result, weekday)
	}
	slices.Sort(result)
	policy := SchedulePolicy{
		Weekdays:    result,
		StartMinute: EarliestMinute,
		EndMinute:   LatestMinute,
	}
	if err := ValidateSchedulePolicy(policy); err != nil {
		return nil, err
	}
	return result, nil
}

func FormatWeekdays(weekdays []int) string {
	values := slices.Clone(weekdays)
	slices.Sort(values)
	parts := make([]string, 0, len(values))
	for _, weekday := range values {
		parts = append(parts, fmt.Sprintf("%d", weekday))
	}
	return strings.Join(parts, ",")
}

func MinuteTime(minute int) string {
	return fmt.Sprintf("%02d:%02d", minute/60, minute%60)
}

func WeekdayName(weekday int) string {
	names := map[int]string{
		1: "Monday",
		2: "Tuesday",
		3: "Wednesday",
		4: "Thursday",
	}
	return names[weekday]
}

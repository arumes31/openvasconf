package customer

import (
	"errors"
	"slices"
	"strings"
	"time"
)

type Customer struct {
	ID                      string
	Name                    string
	SafeName                string
	Description             string
	Tags                    []string
	ScheduleWeekday         int
	ScheduleMinute          int
	Timezone                string
	ScannerID               string
	ScannerName             string
	ScanConfigID            string
	ScanConfigName          string
	PortListID              string
	PortListName            string
	DesiredRevision         int64
	ReconciliationStatus    string
	LastReconciliationError string
	LastSuccessfulReconcile *time.Time
	Reconciliation          ReconciliationProgress
	DeletedAt               *time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time
	Networks                []Network
}

func NormalizeTags(values ...string) ([]string, error) {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, value := range values {
		for tag := range strings.FieldsSeq(strings.ReplaceAll(value, ",", " ")) {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" {
				continue
			}
			if len(tag) > 30 {
				return nil, errors.New("customer: tags must contain at most 30 characters")
			}
			if _, found := seen[tag]; found {
				continue
			}
			if len(result) == 10 {
				return nil, errors.New("customer: at most 10 tags are allowed")
			}
			seen[tag] = struct{}{}
			result = append(result, tag)
		}
	}
	slices.Sort(result)
	return result, nil
}

type Network struct {
	ID         string
	CustomerID string
	Input      string
	Prefix     string
	Class      string
	CreatedAt  time.Time
}

type Selection struct {
	ID   string
	Name string
}

type Settings struct {
	InstallationID string
	Scanner        Selection
	ScanConfig     Selection
	PortList       Selection
	Timezone       string
	SchedulePolicy SchedulePolicy
	UpdatedAt      time.Time
}

type SchedulePolicy struct {
	Weekdays    []int
	StartMinute int
	EndMinute   int
}

type ReconciliationProgress struct {
	Phase               string
	CurrentOperation    string
	CompletedOperations int
	TotalOperations     int
	Attempt             int
	MaxAttempts         int
	NextRetryAt         *time.Time
	TechnicalError      string
	StartedAt           *time.Time
}

func (c Customer) ScheduleTime() string {
	hour := c.ScheduleMinute / 60
	minute := c.ScheduleMinute % 60
	return time.Date(2000, time.January, 1, hour, minute, 0, 0, time.UTC).Format("15:04")
}

func (c Customer) NextSchedule(after time.Time) (time.Time, error) {
	location, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return time.Time{}, err
	}
	local := after.In(location)
	for offset := range 8 {
		date := local.AddDate(0, 0, offset)
		weekday := int(date.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		if weekday != c.ScheduleWeekday {
			continue
		}
		candidate := time.Date(
			date.Year(),
			date.Month(),
			date.Day(),
			c.ScheduleMinute/60,
			c.ScheduleMinute%60,
			0,
			0,
			location,
		)
		if candidate.After(local) {
			return candidate, nil
		}
	}
	return time.Time{}, errors.New("customer: no next schedule occurrence")
}

func (c Customer) EffectiveScanner(settings Settings) Selection {
	if c.ScannerID != "" {
		return Selection{ID: c.ScannerID, Name: c.ScannerName}
	}
	return settings.Scanner
}

func (c Customer) EffectiveScanConfig(settings Settings) Selection {
	if c.ScanConfigID != "" {
		return Selection{ID: c.ScanConfigID, Name: c.ScanConfigName}
	}
	return settings.ScanConfig
}

func (c Customer) EffectivePortList(settings Settings) Selection {
	if c.PortListID != "" {
		return Selection{ID: c.PortListID, Name: c.PortListName}
	}
	return settings.PortList
}

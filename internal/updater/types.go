package updater

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const ProtocolVersion = "1"

var (
	ErrBusy        = errors.New("updater: another operation is active")
	ErrPaused      = errors.New("updater: automatic stack updates are paused")
	ErrUnavailable = errors.New("updater: helper unavailable")
)

type Kind string

const (
	KindCheck Kind = "check"
	KindFeed  Kind = "feed"
	KindStack Kind = "stack"
)

type Trigger string

const (
	TriggerAdmin     Trigger = "admin"
	TriggerScheduled Trigger = "scheduled"
)

type State string

const (
	StateQueued     State = "queued"
	StateWaiting    State = "waiting-for-scans"
	StateRunning    State = "running"
	StateSucceeded  State = "succeeded"
	StateDegraded   State = "degraded"
	StateRolledBack State = "rolled-back"
	StateFailed     State = "failed"
	StateCancelled  State = "cancelled"
)

type Policy struct {
	FeedEnabled               bool   `json:"feed_enabled"`
	FeedMinute                int    `json:"feed_minute"`
	StackEnabled              bool   `json:"stack_enabled"`
	StackWeekday              int    `json:"stack_weekday"`
	StackStartMinute          int    `json:"stack_start_minute"`
	StackWindowMinutes        int    `json:"stack_window_minutes"`
	Timezone                  string `json:"timezone"`
	BackupRetention           int    `json:"backup_retention"`
	VerificationTimeoutMinute int    `json:"verification_timeout_minutes"`
}

func DefaultPolicy(timezone string) Policy {
	return Policy{
		FeedEnabled:               true,
		FeedMinute:                2 * 60,
		StackEnabled:              false,
		StackWeekday:              7,
		StackStartMinute:          3 * 60,
		StackWindowMinutes:        180,
		Timezone:                  timezone,
		BackupRetention:           3,
		VerificationTimeoutMinute: 180,
	}
}

func (p Policy) Validate() error {
	var problems []error
	if p.FeedMinute < 0 || p.FeedMinute >= 24*60 {
		problems = append(problems, errors.New("feed time must be between 00:00 and 23:59"))
	}
	if p.StackWeekday < 1 || p.StackWeekday > 7 {
		problems = append(problems, errors.New("stack weekday must be between 1 and 7"))
	}
	if p.StackStartMinute < 0 || p.StackStartMinute >= 24*60 {
		problems = append(problems, errors.New("maintenance start must be between 00:00 and 23:59"))
	}
	if p.StackWindowMinutes < 30 || p.StackWindowMinutes > 12*60 {
		problems = append(problems, errors.New("maintenance window must be between 30 and 720 minutes"))
	}
	if p.StackStartMinute+p.StackWindowMinutes > 24*60 {
		problems = append(problems, errors.New("maintenance window must end before midnight"))
	}
	if strings.TrimSpace(p.Timezone) == "" {
		problems = append(problems, errors.New("update timezone is required"))
	} else if _, err := time.LoadLocation(p.Timezone); err != nil {
		problems = append(problems, fmt.Errorf("invalid update timezone %q: %w", p.Timezone, err))
	}
	if p.BackupRetention < 1 || p.BackupRetention > 30 {
		problems = append(problems, errors.New("backup retention must be between 1 and 30"))
	}
	if p.VerificationTimeoutMinute < 5 || p.VerificationTimeoutMinute > 12*60 {
		problems = append(problems, errors.New("verification timeout must be between 5 and 720 minutes"))
	}
	return errors.Join(problems...)
}

type Image struct {
	Service       string `json:"service"`
	Repository    string `json:"repository"`
	Tag           string `json:"tag"`
	ID            string `json:"id"`
	containerName string
}

type Feed struct {
	Name             string    `json:"name"`
	Version          string    `json:"version"`
	CurrentlySyncing bool      `json:"currently_syncing"`
	UpdatedAt        time.Time `json:"updated_at,omitempty"`
}

type Operation struct {
	ID           string     `json:"id"`
	Kind         Kind       `json:"kind"`
	Trigger      Trigger    `json:"trigger"`
	State        State      `json:"state"`
	Phase        string     `json:"phase"`
	Detail       string     `json:"detail,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	Backup       string     `json:"-"`
	ImagesBefore []Image    `json:"images_before,omitempty"`
	ImagesAfter  []Image    `json:"images_after,omitempty"`
}

func (o Operation) Terminal() bool {
	switch o.State {
	case StateSucceeded, StateDegraded, StateRolledBack, StateFailed, StateCancelled:
		return true
	default:
		return false
	}
}

type Status struct {
	ProtocolVersion  string      `json:"protocol_version"`
	Available        bool        `json:"available"`
	AutomationPaused bool        `json:"automation_paused"`
	PauseReason      string      `json:"pause_reason,omitempty"`
	Policy           Policy      `json:"policy"`
	Active           *Operation  `json:"active,omitempty"`
	History          []Operation `json:"history"`
	Images           []Image     `json:"images"`
	Feeds            []Feed      `json:"feeds"`
	LastCheckedAt    *time.Time  `json:"last_checked_at,omitempty"`
	NextFeedAt       *time.Time  `json:"next_feed_at,omitempty"`
	NextStackAt      *time.Time  `json:"next_stack_at,omitempty"`
}

type TriggerRequest struct {
	IdempotencyKey string  `json:"idempotency_key"`
	Trigger        Trigger `json:"trigger"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

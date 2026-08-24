package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"openvasconf/internal/id"
)

const maxHistory = 100

var errDeferred = errors.New("updater: operation deferred")

type Runtime interface {
	Validate(ctx context.Context) error
	Snapshot(ctx context.Context, services []string) ([]Image, error)
	ResolvedSnapshot(ctx context.Context, services []string) ([]Image, error)
	PullFeed(ctx context.Context) error
	PullStack(ctx context.Context) error
	ApplyFeed(ctx context.Context) error
	ApplyStack(ctx context.Context) error
	Backup(ctx context.Context, operationID string) (string, error)
	Rollback(ctx context.Context, images []Image, backupPath string) error
	PruneBackups(retain int, protected string) error
	FeedServices() []string
	StackServices() []string
}

type Scanner interface {
	Ping(ctx context.Context) error
	Feeds(ctx context.Context) ([]Feed, error)
	ActiveScans(ctx context.Context) (int, error)
}

type StateStore interface {
	Load() (persistentState, error)
	Save(state persistentState) error
}

type persistentState struct {
	Policy           Policy            `json:"policy"`
	AutomationPaused bool              `json:"automation_paused"`
	PauseReason      string            `json:"pause_reason,omitempty"`
	Active           *Operation        `json:"active,omitempty"`
	BackupPath       string            `json:"backup_path,omitempty"`
	History          []Operation       `json:"history"`
	Images           []Image           `json:"images"`
	Feeds            []Feed            `json:"feeds"`
	LastCheckedAt    *time.Time        `json:"last_checked_at,omitempty"`
	LastFeedDate     string            `json:"last_feed_date,omitempty"`
	LastStackDate    string            `json:"last_stack_date,omitempty"`
	Idempotency      map[string]string `json:"idempotency"`
}

type ControllerOptions struct {
	Runtime          Runtime
	Scanner          Scanner
	Store            StateStore
	Logger           *slog.Logger
	DefaultPolicy    Policy
	ScheduleInterval time.Duration
	PollInterval     time.Duration
	OperationTimeout time.Duration
	Now              func() time.Time
}

type Controller struct {
	runtime          Runtime
	scanner          Scanner
	store            StateStore
	logger           *slog.Logger
	scheduleInterval time.Duration
	pollInterval     time.Duration
	operationTimeout time.Duration
	now              func() time.Time

	mu        sync.Mutex
	persistMu sync.Mutex
	state     persistentState
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewController(options ControllerOptions) (*Controller, error) {
	if options.Runtime == nil || options.Scanner == nil || options.Store == nil {
		return nil, errors.New("updater: runtime, scanner, and state store are required")
	}
	if err := options.DefaultPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("updater: invalid default policy: %w", err)
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.ScheduleInterval <= 0 {
		options.ScheduleInterval = time.Minute
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 30 * time.Second
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	state, err := options.Store.Load()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(state.Policy.Timezone) == "" {
		state.Policy = options.DefaultPolicy
	}
	if err := state.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("updater: invalid stored policy: %w", err)
	}
	if state.Idempotency == nil {
		state.Idempotency = make(map[string]string)
	}
	return &Controller{
		runtime:          options.Runtime,
		scanner:          options.Scanner,
		store:            options.Store,
		logger:           options.Logger,
		scheduleInterval: options.ScheduleInterval,
		pollInterval:     options.PollInterval,
		operationTimeout: options.OperationTimeout,
		now:              options.Now,
		state:            state,
	}, nil
}

func (c *Controller) Start(parent context.Context) error {
	c.mu.Lock()
	if c.ctx != nil {
		c.mu.Unlock()
		return errors.New("updater: controller already started")
	}
	c.ctx, c.cancel = context.WithCancel(parent)
	interrupted := cloneOperation(c.state.Active)
	if interrupted != nil {
		interrupted.Backup = c.state.BackupPath
	}
	c.mu.Unlock()

	if err := c.runtime.Validate(c.ctx); err != nil {
		c.cancel()
		c.mu.Lock()
		c.ctx = nil
		c.cancel = nil
		c.mu.Unlock()
		return fmt.Errorf("updater preflight failed: %w", err)
	}
	if interrupted != nil && !interrupted.Terminal() {
		c.wg.Add(1)
		go c.recoverInterrupted(*interrupted)
	}
	c.wg.Add(1)
	go c.scheduleLoop()
	return nil
}

func (c *Controller) Close() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.wg.Wait()
}

func (c *Controller) Status(_ context.Context) (Status, error) {
	c.mu.Lock()
	state := cloneState(c.state)
	c.mu.Unlock()
	now := c.now()
	return Status{
		ProtocolVersion:  ProtocolVersion,
		Available:        true,
		AutomationPaused: state.AutomationPaused,
		PauseReason:      state.PauseReason,
		Policy:           state.Policy,
		Active:           cloneOperation(state.Active),
		History:          append([]Operation(nil), state.History...),
		Images:           append([]Image(nil), state.Images...),
		Feeds:            append([]Feed(nil), state.Feeds...),
		LastCheckedAt:    cloneTime(state.LastCheckedAt),
		NextFeedAt:       nextFeedTime(state.Policy, now),
		NextStackAt:      nextStackTime(state.Policy, now),
	}, nil
}

func (c *Controller) Configure(_ context.Context, policy Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	c.state.Policy = policy
	c.mu.Unlock()
	return c.saveState()
}

func (c *Controller) Trigger(
	_ context.Context,
	kind Kind,
	request TriggerRequest,
) (Operation, error) {
	if kind != KindCheck && kind != KindFeed && kind != KindStack {
		return Operation{}, fmt.Errorf("updater: unsupported operation kind %q", kind)
	}
	if request.Trigger != TriggerAdmin && request.Trigger != TriggerScheduled {
		return Operation{}, errors.New("updater: invalid operation trigger")
	}
	if !validIdentifier(request.IdempotencyKey) {
		return Operation{}, errors.New("updater: invalid idempotency key")
	}
	c.mu.Lock()
	if existingID := c.state.Idempotency[request.IdempotencyKey]; existingID != "" {
		operation, ok := c.operationLocked(existingID)
		c.mu.Unlock()
		if !ok {
			return Operation{}, errors.New("updater: idempotency record is inconsistent")
		}
		return operation, nil
	}
	if c.state.Active != nil && !c.state.Active.Terminal() {
		c.mu.Unlock()
		return Operation{}, ErrBusy
	}
	if kind == KindStack && c.state.AutomationPaused {
		c.mu.Unlock()
		return Operation{}, ErrPaused
	}
	if c.ctx == nil || c.ctx.Err() != nil {
		c.mu.Unlock()
		return Operation{}, ErrUnavailable
	}
	operationID, err := id.New()
	if err != nil {
		c.mu.Unlock()
		return Operation{}, err
	}
	operation := Operation{
		ID: operationID, Kind: kind, Trigger: request.Trigger,
		State: StateQueued, Phase: "queued", StartedAt: c.now().UTC(),
	}
	c.state.Active = cloneOperation(&operation)
	c.state.BackupPath = ""
	c.state.Idempotency[request.IdempotencyKey] = operation.ID
	c.trimIdempotencyLocked()
	c.mu.Unlock()
	if err := c.saveState(); err != nil {
		c.mu.Lock()
		if c.state.Active != nil && c.state.Active.ID == operation.ID {
			c.state.Active = nil
			delete(c.state.Idempotency, request.IdempotencyKey)
		}
		c.mu.Unlock()
		return Operation{}, err
	}
	c.wg.Add(1)
	go c.execute(operation.ID)
	return operation, nil
}

func (c *Controller) Acknowledge(_ context.Context) error {
	c.mu.Lock()
	c.state.AutomationPaused = false
	c.state.PauseReason = ""
	c.mu.Unlock()
	return c.saveState()
}

func (c *Controller) scheduleLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.scheduleInterval)
	defer ticker.Stop()
	c.checkSchedule()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkSchedule()
		}
	}
}

func (c *Controller) checkSchedule() {
	c.mu.Lock()
	state := cloneState(c.state)
	c.mu.Unlock()
	if state.Active != nil && !state.Active.Terminal() {
		return
	}
	location, err := time.LoadLocation(state.Policy.Timezone)
	if err != nil {
		return
	}
	now := c.now().In(location)
	date := now.Format(time.DateOnly)
	minute := now.Hour()*60 + now.Minute()
	if state.Policy.FeedEnabled && minute >= state.Policy.FeedMinute && state.LastFeedDate != date {
		_, _ = c.Trigger(c.ctx, KindFeed, TriggerRequest{
			IdempotencyKey: "feed-" + now.Format("20060102"), Trigger: TriggerScheduled,
		})
		return
	}
	windowEnd := state.Policy.StackStartMinute + state.Policy.StackWindowMinutes
	if state.Policy.StackEnabled && !state.AutomationPaused && int(now.Weekday()) == state.Policy.StackWeekday%7 &&
		minute >= state.Policy.StackStartMinute && minute < windowEnd && state.LastStackDate != date {
		_, _ = c.Trigger(c.ctx, KindStack, TriggerRequest{
			IdempotencyKey: "stack-" + now.Format("20060102"), Trigger: TriggerScheduled,
		})
	}
}

func (c *Controller) execute(operationID string) {
	defer c.wg.Done()
	c.mu.Lock()
	operation, ok := c.operationLocked(operationID)
	policy := c.state.Policy
	ctx := c.ctx
	c.mu.Unlock()
	if !ok {
		return
	}
	timeout := time.Duration(policy.VerificationTimeoutMinute) * time.Minute
	if c.operationTimeout > 0 {
		timeout = c.operationTimeout
	}
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var err error
	switch operation.Kind {
	case KindCheck:
		err = c.runCheck(operationCtx, operationID)
	case KindFeed:
		err = c.runFeed(operationCtx, operationID)
	case KindStack:
		err = c.runStack(operationCtx, operationID, operation.Trigger, policy)
	}
	if err == nil {
		c.finish(operationID, StateSucceeded, "completed")
		return
	}
	if errors.Is(err, context.Canceled) && c.ctx.Err() != nil {
		return
	}
	c.logger.Error("update operation failed", "operation", operationID, "kind", operation.Kind, "error", err)
	c.finish(operationID, StateFailed, safeFailure(operation.Kind))
}

func (c *Controller) runCheck(ctx context.Context, operationID string) error {
	c.phase(operationID, StateRunning, "preflight", "Checking Docker, Compose, GMP, feeds, and images.")
	if err := c.runtime.Validate(ctx); err != nil {
		return err
	}
	if err := c.scanner.Ping(ctx); err != nil {
		return fmt.Errorf("checking GMP: %w", err)
	}
	images, err := c.runtime.Snapshot(ctx, c.runtime.StackServices())
	if err != nil {
		return err
	}
	feeds, err := c.scanner.Feeds(ctx)
	if err != nil {
		return fmt.Errorf("checking feeds: %w", err)
	}
	now := c.now().UTC()
	c.mu.Lock()
	c.state.Images = append([]Image(nil), images...)
	c.state.Feeds = append([]Feed(nil), feeds...)
	c.state.LastCheckedAt = &now
	c.mu.Unlock()
	return c.saveState()
}

func (c *Controller) runFeed(ctx context.Context, operationID string) error {
	c.phase(operationID, StateRunning, "preflight", "Validating the feed update boundary.")
	if err := c.runtime.Validate(ctx); err != nil {
		return err
	}
	beforeImages, err := c.runtime.Snapshot(ctx, c.runtime.FeedServices())
	if err != nil {
		return err
	}
	beforeFeeds, err := c.scanner.Feeds(ctx)
	if err != nil {
		return err
	}
	c.setImages(operationID, beforeImages, nil)
	c.phase(operationID, StateRunning, "pulling", "Pulling approved Greenbone feed images.")
	if err := c.runtime.PullFeed(ctx); err != nil {
		return err
	}
	afterImages, err := c.runtime.ResolvedSnapshot(ctx, c.runtime.FeedServices())
	if err != nil {
		return err
	}
	c.setImages(operationID, beforeImages, afterImages)
	if !imagesChanged(beforeImages, afterImages) {
		c.recordScheduleCompletion(KindFeed)
		return nil
	}
	c.phase(operationID, StateRunning, "applying", "Copying changed feed data into Greenbone volumes.")
	if err := c.runtime.ApplyFeed(ctx); err != nil {
		return err
	}
	c.phase(operationID, StateRunning, "importing", "Waiting for Greenbone to import the refreshed feed.")
	feeds, err := c.waitForFeeds(ctx, beforeFeeds, true)
	if err != nil {
		c.finish(operationID, StateDegraded, "Feed images updated; Greenbone import is still pending.")
		return nil
	}
	c.mu.Lock()
	c.state.Feeds = feeds
	c.mu.Unlock()
	c.recordScheduleCompletion(KindFeed)
	return nil
}

func (c *Controller) runStack(
	ctx context.Context,
	operationID string,
	trigger Trigger,
	policy Policy,
) error {
	if err := c.waitForScans(ctx, operationID, trigger, policy); err != nil {
		if errors.Is(err, errDeferred) {
			return nil
		}
		return err
	}
	c.phase(operationID, StateRunning, "preflight", "Validating Docker, Compose, GMP, and scanner state.")
	if err := c.runtime.Validate(ctx); err != nil {
		return err
	}
	if err := c.scanner.Ping(ctx); err != nil {
		return err
	}
	before, err := c.runtime.Snapshot(ctx, c.runtime.StackServices())
	if err != nil {
		return err
	}
	c.setImages(operationID, before, nil)
	c.phase(operationID, StateRunning, "checkpoint", "Creating the Greenbone database checkpoint.")
	backup, err := c.runtime.Backup(ctx, operationID)
	if err != nil {
		return err
	}
	if err := c.setBackup(operationID, backup); err != nil {
		return fmt.Errorf("persisting stack checkpoint: %w", err)
	}
	c.phase(operationID, StateRunning, "staging", "Pulling approved Greenbone service images.")
	if err := c.runtime.PullStack(ctx); err != nil {
		return err
	}
	after, err := c.runtime.ResolvedSnapshot(ctx, c.runtime.StackServices())
	if err != nil {
		return err
	}
	c.setImages(operationID, before, after)
	if !imagesChanged(before, after) {
		c.recordScheduleCompletion(KindStack)
		return c.runtime.PruneBackups(policy.BackupRetention, "")
	}
	c.phase(operationID, StateRunning, "applying", "Recreating changed Greenbone services.")
	if err := c.runtime.ApplyStack(ctx); err != nil {
		return c.rollback(ctx, operationID, before, backup, err)
	}
	c.phase(operationID, StateRunning, "verifying", "Verifying GMP, scanner, and feed availability.")
	if err := c.waitForScanner(ctx); err != nil {
		return c.rollback(ctx, operationID, before, backup, err)
	}
	c.mu.Lock()
	c.state.Images = append([]Image(nil), after...)
	c.mu.Unlock()
	c.persistBestEffort()
	c.recordScheduleCompletion(KindStack)
	if err := c.runtime.PruneBackups(policy.BackupRetention, ""); err != nil {
		c.logger.Warn("pruning updater backups failed", "error", err)
	}
	return nil
}

func (c *Controller) waitForScans(
	ctx context.Context,
	operationID string,
	trigger Trigger,
	policy Policy,
) error {
	for {
		active, err := c.scanner.ActiveScans(ctx)
		if err != nil {
			return fmt.Errorf("checking active scans: %w", err)
		}
		if active == 0 {
			return nil
		}
		c.phase(operationID, StateWaiting, "waiting-for-scans", fmt.Sprintf("Waiting for %d active scan(s) to finish.", active))
		if trigger == TriggerScheduled && scheduledWindowExpired(c.now(), policy) {
			c.finish(operationID, StateCancelled, "Maintenance window ended while scans were active; deferred to the next window.")
			c.recordScheduleCompletion(KindStack)
			return errDeferred
		}
		if err := wait(ctx, c.pollInterval); err != nil {
			return err
		}
	}
}

func (c *Controller) waitForScanner(ctx context.Context) error {
	for {
		if err := c.scanner.Ping(ctx); err == nil {
			if _, feedErr := c.scanner.Feeds(ctx); feedErr == nil {
				return nil
			}
		}
		if err := wait(ctx, c.pollInterval); err != nil {
			return err
		}
	}
}

func (c *Controller) waitForFeeds(ctx context.Context, before []Feed, requireAdvance bool) ([]Feed, error) {
	for {
		feeds, err := c.scanner.Feeds(ctx)
		if err == nil && !feedsSyncing(feeds) && (!requireAdvance || feedsAdvanced(before, feeds)) {
			return feeds, nil
		}
		if err := wait(ctx, c.pollInterval); err != nil {
			return nil, err
		}
	}
}

func (c *Controller) rollback(
	ctx context.Context,
	operationID string,
	images []Image,
	backup string,
	cause error,
) error {
	c.phase(operationID, StateRunning, "rolling-back", "Verification failed; restoring the previous stack checkpoint.")
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
	if c.operationTimeout > 0 {
		rollbackCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), c.operationTimeout)
	}
	defer cancel()
	if err := c.runtime.Rollback(rollbackCtx, images, backup); err != nil {
		c.pauseAutomation("Stack rollback failed; inspect the updater logs and Greenbone state.")
		return errors.Join(cause, fmt.Errorf("rolling back: %w", err))
	}
	if err := c.waitForScanner(rollbackCtx); err != nil {
		c.pauseAutomation("The restored stack could not be verified; manual recovery is required.")
		return errors.Join(cause, fmt.Errorf("verifying rollback: %w", err))
	}
	c.finish(operationID, StateRolledBack, "Upgrade failed and the previous Greenbone stack was restored.")
	c.pauseAutomation("The last stack upgrade was rolled back; acknowledge it before automatic upgrades resume.")
	return nil
}

func (c *Controller) recoverInterrupted(operation Operation) {
	defer c.wg.Done()
	if operation.Kind == KindStack && (operation.Phase == "applying" || operation.Phase == "verifying" || operation.Phase == "rolling-back") {
		c.phase(operation.ID, StateRunning, "rolling-back", "Recovering an interrupted upgrade from its checkpoint.")
		ctx, cancel := context.WithTimeout(c.ctx, 30*time.Minute)
		defer cancel()
		if err := c.runtime.Rollback(ctx, operation.ImagesBefore, operation.Backup); err != nil {
			c.logger.Error("interrupted upgrade recovery failed", "operation", operation.ID, "error", err)
			c.finish(operation.ID, StateFailed, "Interrupted upgrade recovery failed; manual recovery is required.")
			c.pauseAutomation("Interrupted stack upgrade could not be recovered.")
			return
		}
		c.finish(operation.ID, StateRolledBack, "Interrupted upgrade recovered to the previous checkpoint.")
		c.pauseAutomation("An interrupted stack upgrade was rolled back; acknowledge it before automation resumes.")
		return
	}
	c.finish(operation.ID, StateDegraded, "An interrupted operation was stopped safely; run it again.")
}

func (c *Controller) phase(operationID string, state State, phase, detail string) {
	c.mu.Lock()
	if c.state.Active != nil && c.state.Active.ID == operationID {
		c.state.Active.State = state
		c.state.Active.Phase = phase
		c.state.Active.Detail = truncate(detail, 500)
	}
	c.mu.Unlock()
	c.persistBestEffort()
}

func (c *Controller) setImages(operationID string, before, after []Image) {
	c.mu.Lock()
	if c.state.Active != nil && c.state.Active.ID == operationID {
		c.state.Active.ImagesBefore = append([]Image(nil), before...)
		c.state.Active.ImagesAfter = append([]Image(nil), after...)
	}
	c.mu.Unlock()
	c.persistBestEffort()
}

func (c *Controller) setBackup(operationID, backup string) error {
	c.mu.Lock()
	if c.state.Active != nil && c.state.Active.ID == operationID {
		c.state.Active.Backup = backup
		c.state.BackupPath = backup
	}
	c.mu.Unlock()
	return c.saveState()
}

func (c *Controller) finish(operationID string, state State, detail string) {
	now := c.now().UTC()
	c.mu.Lock()
	if c.state.Active == nil || c.state.Active.ID != operationID || c.state.Active.Terminal() {
		c.mu.Unlock()
		return
	}
	c.state.Active.State = state
	c.state.Active.Phase = string(state)
	c.state.Active.Detail = truncate(detail, 500)
	c.state.Active.FinishedAt = &now
	c.state.History = append([]Operation{*cloneOperation(c.state.Active)}, c.state.History...)
	c.state.BackupPath = ""
	if len(c.state.History) > maxHistory {
		c.state.History = c.state.History[:maxHistory]
	}
	c.mu.Unlock()
	c.persistBestEffort()
}

func (c *Controller) recordScheduleCompletion(kind Kind) {
	c.mu.Lock()
	location, err := time.LoadLocation(c.state.Policy.Timezone)
	if err == nil {
		date := c.now().In(location).Format(time.DateOnly)
		switch kind {
		case KindFeed:
			c.state.LastFeedDate = date
		case KindStack:
			c.state.LastStackDate = date
		}
	}
	c.mu.Unlock()
	c.persistBestEffort()
}

func (c *Controller) pauseAutomation(reason string) {
	c.mu.Lock()
	c.state.AutomationPaused = true
	c.state.PauseReason = truncate(reason, 500)
	c.mu.Unlock()
	c.persistBestEffort()
}

func (c *Controller) operationLocked(operationID string) (Operation, bool) {
	if c.state.Active != nil && c.state.Active.ID == operationID {
		return *cloneOperation(c.state.Active), true
	}
	for _, operation := range c.state.History {
		if operation.ID == operationID {
			return operation, true
		}
	}
	return Operation{}, false
}

func (c *Controller) trimIdempotencyLocked() {
	if len(c.state.Idempotency) <= maxHistory+1 {
		return
	}
	keep := make(map[string]bool, len(c.state.History)+1)
	if c.state.Active != nil {
		keep[c.state.Active.ID] = true
	}
	for _, operation := range c.state.History {
		keep[operation.ID] = true
	}
	for key, operationID := range c.state.Idempotency {
		if !keep[operationID] {
			delete(c.state.Idempotency, key)
		}
	}
}

func (c *Controller) saveState() error {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	c.mu.Lock()
	state := cloneState(c.state)
	c.mu.Unlock()
	return c.store.Save(state)
}

func (c *Controller) persistBestEffort() {
	if err := c.saveState(); err != nil {
		c.logger.Error("persisting updater state failed", "error", err)
	}
}

func imagesChanged(before, after []Image) bool {
	beforeIDs := make(map[string]string, len(before))
	for _, image := range before {
		beforeIDs[image.Service] = image.ID
	}
	if len(beforeIDs) != len(after) {
		return true
	}
	for _, image := range after {
		if beforeIDs[image.Service] != image.ID {
			return true
		}
	}
	return false
}

func feedsSyncing(feeds []Feed) bool {
	for _, feed := range feeds {
		if feed.CurrentlySyncing {
			return true
		}
	}
	return false
}

func feedsAdvanced(before, after []Feed) bool {
	versions := make(map[string]Feed, len(before))
	for _, feed := range before {
		versions[feed.Name] = feed
	}
	for _, feed := range after {
		previous, ok := versions[feed.Name]
		if !ok || feed.Version != previous.Version || feed.UpdatedAt.After(previous.UpdatedAt) {
			return true
		}
	}
	return false
}

func scheduledWindowExpired(now time.Time, policy Policy) bool {
	location, err := time.LoadLocation(policy.Timezone)
	if err != nil {
		return true
	}
	local := now.In(location)
	if int(local.Weekday()) != policy.StackWeekday%7 {
		return true
	}
	minute := local.Hour()*60 + local.Minute()
	return minute >= policy.StackStartMinute+policy.StackWindowMinutes
}

func nextFeedTime(policy Policy, now time.Time) *time.Time {
	if !policy.FeedEnabled {
		return nil
	}
	location, err := time.LoadLocation(policy.Timezone)
	if err != nil {
		return nil
	}
	local := now.In(location)
	next := time.Date(local.Year(), local.Month(), local.Day(), policy.FeedMinute/60, policy.FeedMinute%60, 0, 0, location)
	if !next.After(local) {
		next = next.AddDate(0, 0, 1)
	}
	return &next
}

func nextStackTime(policy Policy, now time.Time) *time.Time {
	if !policy.StackEnabled {
		return nil
	}
	location, err := time.LoadLocation(policy.Timezone)
	if err != nil {
		return nil
	}
	local := now.In(location)
	days := (policy.StackWeekday%7 - int(local.Weekday()) + 7) % 7
	next := time.Date(local.Year(), local.Month(), local.Day(), policy.StackStartMinute/60, policy.StackStartMinute%60, 0, 0, location).AddDate(0, 0, days)
	if !next.After(local) {
		next = next.AddDate(0, 0, 7)
	}
	return &next
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func safeFailure(kind Kind) string {
	switch kind {
	case KindCheck:
		return "Update preflight failed. Review the updater logs."
	case KindFeed:
		return "Feed refresh failed. Existing feed data remains available; review the updater logs."
	case KindStack:
		return "Greenbone stack upgrade failed. Review the updater and Greenbone logs."
	default:
		return "Update operation failed. Review the updater logs."
	}
}

func truncate(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) <= maximum {
		return value
	}
	return value[:maximum] + "…"
}

func cloneState(state persistentState) persistentState {
	result := state
	result.Active = cloneOperation(state.Active)
	result.History = append([]Operation(nil), state.History...)
	result.Images = append([]Image(nil), state.Images...)
	result.Feeds = append([]Feed(nil), state.Feeds...)
	result.LastCheckedAt = cloneTime(state.LastCheckedAt)
	result.Idempotency = make(map[string]string, len(state.Idempotency))
	for key, value := range state.Idempotency {
		result.Idempotency[key] = value
	}
	return result
}

func cloneOperation(operation *Operation) *Operation {
	if operation == nil {
		return nil
	}
	result := *operation
	result.FinishedAt = cloneTime(operation.FinishedAt)
	result.ImagesBefore = append([]Image(nil), operation.ImagesBefore...)
	result.ImagesAfter = append([]Image(nil), operation.ImagesAfter...)
	return &result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

type FileStateStore struct {
	directory string
	name      string
}

func NewFileStateStore(path string) (*FileStateStore, error) {
	clean, ok := absolutePath(path)
	if !ok {
		return nil, errors.New("updater: state path must be absolute")
	}
	return &FileStateStore{directory: filepath.Dir(clean), name: filepath.Base(clean)}, nil
}

func (s *FileStateStore) Load() (persistentState, error) {
	root, err := os.OpenRoot(s.directory)
	if err != nil {
		return persistentState{}, fmt.Errorf("opening updater state directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	contents, err := root.ReadFile(s.name)
	if errors.Is(err, os.ErrNotExist) {
		return persistentState{}, nil
	}
	if err != nil {
		return persistentState{}, fmt.Errorf("reading updater state: %w", err)
	}
	var state persistentState
	if err := json.Unmarshal(contents, &state); err != nil {
		return persistentState{}, fmt.Errorf("decoding updater state: %w", err)
	}
	return state, nil
}

func (s *FileStateStore) Save(state persistentState) error {
	root, err := os.OpenRoot(s.directory)
	if err != nil {
		return fmt.Errorf("opening updater state directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	contents, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding updater state: %w", err)
	}
	temporary := s.name + ".tmp"
	if err := root.WriteFile(temporary, contents, 0o600); err != nil {
		return fmt.Errorf("writing updater state: %w", err)
	}
	if err := root.Rename(temporary, s.name); err != nil {
		return fmt.Errorf("replacing updater state: %w", err)
	}
	return nil
}

func sortedImages(images []Image) []Image {
	result := append([]Image(nil), images...)
	sort.Slice(result, func(left, right int) bool { return result[left].Service < result[right].Service })
	return result
}

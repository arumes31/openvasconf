package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
	"openvasconf/internal/networkplan"
	"openvasconf/internal/store"
)

var ErrOwnershipMismatch = errors.New("reconcile: greenbone ownership marker mismatch")

const (
	maxReconcileAttempts = 3
	initialRetryBackoff  = 250 * time.Millisecond
)

type Repository interface {
	Settings(ctx context.Context) (customer.Settings, error)
	UpdateSettings(ctx context.Context, settings customer.Settings) error
	Customers(ctx context.Context, includeDeleted bool) ([]customer.Customer, error)
	ManagedResources(ctx context.Context, customerID string) ([]store.ManagedResource, error)
	UpsertManagedResource(ctx context.Context, resource store.ManagedResource) error
	DeleteManagedResource(ctx context.Context, customerID, kind, class string, sequence int) error
	SetCustomerReconciliation(ctx context.Context, customerID, status, lastError string) error
	AddAuditEvent(ctx context.Context, event store.AuditEvent) error
	BeginReconcileRun(ctx context.Context, customerID string) (int64, error)
	FinishReconcileRun(ctx context.Context, runID int64, runError error) error
	UpdateReconcileProgress(ctx context.Context, runID int64, customerID string, progress store.ReconcileProgress) error
	AddReconcileOperation(ctx context.Context, operation store.ReconcileOperation) error
}

type Greenbone interface {
	Ping(ctx context.Context) (string, error)
	Options(ctx context.Context) (gmp.Options, error)
	CreateSchedule(ctx context.Context, value gmp.Schedule) (string, error)
	ModifySchedule(ctx context.Context, scheduleID string, value gmp.Schedule) error
	DeleteSchedule(ctx context.Context, scheduleID string) error
	CreateTarget(ctx context.Context, value gmp.Target) (string, error)
	ModifyTarget(ctx context.Context, targetID string, value gmp.Target) error
	DeleteTarget(ctx context.Context, targetID string) error
	CreateTask(ctx context.Context, value gmp.Task) (string, error)
	ModifyTask(ctx context.Context, taskID string, value gmp.Task) error
	DeleteTask(ctx context.Context, taskID string) error
	ResourceComment(ctx context.Context, kind, resourceID string) (string, error)
	FindResource(ctx context.Context, kind, ownershipMarker string) (string, bool, error)
}

type Reconciler struct {
	repository Repository
	greenbone  Greenbone
	logger     *slog.Logger
	interval   time.Duration
	trigger    chan []string
	mu         sync.Mutex
	trackers   map[string]*progressTracker
}

func New(
	repository Repository,
	greenbone Greenbone,
	logger *slog.Logger,
	interval time.Duration,
) *Reconciler {
	return &Reconciler{
		repository: repository,
		greenbone:  greenbone,
		logger:     logger,
		interval:   interval,
		trigger:    make(chan []string, 8),
		trackers:   make(map[string]*progressTracker),
	}
}

func (r *Reconciler) Trigger() {
	select {
	case r.trigger <- nil:
	default:
	}
}

func (r *Reconciler) TriggerCustomers(customerIDs []string) {
	if len(customerIDs) == 0 {
		r.Trigger()
		return
	}
	select {
	case r.trigger <- slices.Clone(customerIDs):
	default:
		r.Trigger()
	}
}

func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	r.runAndLog(ctx, nil)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runAndLog(ctx, nil)
		case customerIDs := <-r.trigger:
			r.runAndLog(ctx, customerIDs)
		}
	}
}

func (r *Reconciler) runAndLog(ctx context.Context, customerIDs []string) {
	var err error
	backoff := initialRetryBackoff
	for attempt := 1; attempt <= maxReconcileAttempts; attempt++ {
		err = r.runCustomersOnce(ctx, customerIDs, attempt)
		if err == nil || !isTransient(err) || attempt == maxReconcileAttempts {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			err = ctx.Err()
		case <-timer.C:
		}
		if ctx.Err() != nil {
			break
		}
		backoff *= 2
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Error("reconciliation failed", "error", err)
	}
}

func retryTransient(
	ctx context.Context,
	maxAttempts int,
	initialBackoff time.Duration,
	operation func() error,
) error {
	backoff := initialBackoff
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := operation()
		if err == nil || !isTransient(err) || attempt == maxAttempts {
			return err
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}
	return nil
}

func isTransient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var protocolError *gmp.ProtocolError
	if errors.As(err, &protocolError) {
		return strings.HasPrefix(protocolError.Status, "5")
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (r *Reconciler) RunOnce(ctx context.Context) error {
	return r.runCustomersOnce(ctx, nil, 1)
}

func (r *Reconciler) RunCustomersOnce(ctx context.Context, customerIDs []string) error {
	return r.runCustomersOnce(ctx, customerIDs, 1)
}

func (r *Reconciler) runCustomersOnce(ctx context.Context, customerIDs []string, attempt int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	settings, err := r.repository.Settings(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: loading settings: %w", err)
	}
	settings, err = r.ensureDefaultSettings(ctx, settings)
	if err != nil {
		return err
	}
	customers, err := r.repository.Customers(ctx, true)
	if err != nil {
		return fmt.Errorf("reconcile: loading customers: %w", err)
	}

	errorsFound := make([]error, 0)
	selected := make(map[string]struct{}, len(customerIDs))
	for _, customerID := range customerIDs {
		selected[customerID] = struct{}{}
	}
	for _, value := range customers {
		if len(selected) > 0 {
			if _, ok := selected[value.ID]; !ok {
				continue
			}
		}
		if ctx.Err() != nil {
			return errors.Join(append(errorsFound, ctx.Err())...)
		}
		if err := r.reconcileCustomer(ctx, settings, value, attempt); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("customer %s: %w", value.ID, err))
		}
	}
	return errors.Join(errorsFound...)
}

func (r *Reconciler) ensureDefaultSettings(
	ctx context.Context,
	settings customer.Settings,
) (customer.Settings, error) {
	isComplete := settings.Scanner.ID != "" &&
		settings.ScanConfig.ID != "" &&
		settings.PortList.ID != ""
	if isComplete {
		return settings, nil
	}

	options, err := r.greenbone.Options(ctx)
	if err != nil {
		return customer.Settings{}, fmt.Errorf("reconcile: loading greenbone defaults: %w", err)
	}
	if settings.Scanner.ID == "" {
		settings.Scanner, err = findOption(options.Scanners, "OpenVAS Default")
		if err != nil {
			return customer.Settings{}, err
		}
	}
	if settings.ScanConfig.ID == "" {
		settings.ScanConfig, err = findOption(options.ScanConfigs, "Full and fast")
		if err != nil {
			return customer.Settings{}, err
		}
	}
	if settings.PortList.ID == "" {
		settings.PortList, err = findOption(options.PortLists, "All IANA assigned TCP")
		if err != nil {
			return customer.Settings{}, err
		}
	}
	if err := r.repository.UpdateSettings(ctx, settings); err != nil {
		return customer.Settings{}, fmt.Errorf("reconcile: saving greenbone defaults: %w", err)
	}
	return settings, nil
}

func findOption(options []gmp.Option, name string) (customer.Selection, error) {
	for _, option := range options {
		if option.Name == name {
			return customer.Selection{ID: option.ID, Name: option.Name}, nil
		}
	}
	return customer.Selection{}, fmt.Errorf(
		"reconcile: greenbone object %q is not available; feed data may still be loading",
		name,
	)
}

func (r *Reconciler) reconcileCustomer(
	ctx context.Context,
	settings customer.Settings,
	value customer.Customer,
	attempt int,
) (resultErr error) {
	runID, err := r.repository.BeginReconcileRun(ctx, value.ID)
	if err != nil {
		return err
	}
	tracker := &progressTracker{
		repository: r.repository, runID: runID, customerID: value.ID,
		attempt: attempt, maxAttempts: maxReconcileAttempts,
	}
	r.trackers[value.ID] = tracker
	defer func() {
		tracker.fail(ctx, resultErr)
		delete(r.trackers, value.ID)
		finishErr := r.repository.FinishReconcileRun(ctx, runID, resultErr)
		if finishErr != nil {
			resultErr = errors.Join(resultErr, finishErr)
		}
	}()

	if err := r.repository.SetCustomerReconciliation(ctx, value.ID, "syncing", ""); err != nil {
		return err
	}
	if value.DeletedAt != nil {
		tracker.setTotal(ctx, 1)
		if err := r.cleanupCustomer(ctx, value.ID); err != nil {
			_ = r.repository.SetCustomerReconciliation(ctx, value.ID, "error", safeReconcileError(err))
			return err
		}
		return r.repository.SetCustomerReconciliation(ctx, value.ID, "deleted", "")
	}

	if err := validateSelections(settings, value); err != nil {
		_ = r.repository.SetCustomerReconciliation(ctx, value.ID, "error", safeReconcileError(err))
		return err
	}
	plan, err := networkplan.Build(networkplan.Input{
		CustomerName: value.Name,
		Networks:     networkInputs(value.Networks),
	})
	if err != nil {
		_ = r.repository.SetCustomerReconciliation(ctx, value.ID, "error", safeReconcileError(err))
		return err
	}
	tracker.setTotal(ctx, 1+len(plan.Targets)*2)

	existing, err := r.resourceMap(ctx, value.ID)
	if err != nil {
		return err
	}
	scheduleID, desiredKeys, err := r.applyDesired(ctx, settings, value, plan, existing)
	if err != nil {
		_ = r.repository.SetCustomerReconciliation(ctx, value.ID, "error", safeReconcileError(err))
		return err
	}
	if scheduleID == "" {
		return errors.New("reconcile: schedule id is empty after apply")
	}
	if err := r.cleanupSurplus(ctx, value.ID, existing, desiredKeys); err != nil {
		_ = r.repository.SetCustomerReconciliation(ctx, value.ID, "error", safeReconcileError(err))
		return err
	}
	return r.repository.SetCustomerReconciliation(ctx, value.ID, "applied", "")
}

func validateSelections(settings customer.Settings, value customer.Customer) error {
	selections := []struct {
		name      string
		selection customer.Selection
	}{
		{name: "scanner", selection: value.EffectiveScanner(settings)},
		{name: "scan configuration", selection: value.EffectiveScanConfig(settings)},
		{name: "port list", selection: value.EffectivePortList(settings)},
	}
	for _, item := range selections {
		if item.selection.ID == "" {
			return fmt.Errorf("reconcile: %s is not configured", item.name)
		}
	}
	return nil
}

func networkInputs(networks []customer.Network) []string {
	result := make([]string, 0, len(networks))
	for _, network := range networks {
		result = append(result, network.Prefix)
	}
	return result
}

type resourceKey struct {
	kind     string
	class    string
	sequence int
}

func (r *Reconciler) resourceMap(
	ctx context.Context,
	customerID string,
) (map[resourceKey]store.ManagedResource, error) {
	resources, err := r.repository.ManagedResources(ctx, customerID)
	if err != nil {
		return nil, err
	}
	result := make(map[resourceKey]store.ManagedResource, len(resources))
	for _, resource := range resources {
		result[key(resource.Kind, resource.Class, resource.Sequence)] = resource
	}
	return result, nil
}

func key(kind, class string, sequence int) resourceKey {
	return resourceKey{kind: kind, class: class, sequence: sequence}
}

func (r *Reconciler) applyDesired(
	ctx context.Context,
	settings customer.Settings,
	value customer.Customer,
	plan networkplan.Plan,
	existing map[resourceKey]store.ManagedResource,
) (string, map[resourceKey]struct{}, error) {
	desired := make(map[resourceKey]struct{}, 1+len(plan.Targets)*2)
	scheduleKey := key("schedule", "", 0)
	scheduleMarker := ownershipMarker(settings.InstallationID, value.ID, scheduleKey)
	schedule := gmp.Schedule{
		Name:      value.SafeName + "_Weekly_Schedule",
		Comment:   scheduleMarker,
		ICalendar: weeklyCalendar(value),
		Timezone:  value.Timezone,
	}
	scheduleResource, err := r.applySchedule(ctx, value.ID, scheduleKey, schedule, scheduleMarker, existing)
	if err != nil {
		return "", nil, err
	}
	desired[scheduleKey] = struct{}{}

	for _, targetPlan := range plan.Targets {
		targetKey := key("target", string(targetPlan.Class), targetPlan.Sequence)
		taskKey := key("task", string(targetPlan.Class), targetPlan.Sequence)
		targetMarker := ownershipMarker(settings.InstallationID, value.ID, targetKey)
		target := gmp.Target{
			Name:       targetPlan.Name,
			Comment:    targetMarker,
			Hosts:      gmpHostSpecifications(targetPlan.Prefixes),
			PortListID: value.EffectivePortList(settings).ID,
		}
		if err := r.releaseTaskForTargetChange(
			ctx,
			value.ID,
			targetKey,
			taskKey,
			desiredHash(target),
			existing,
		); err != nil {
			return "", nil, err
		}
		targetResource, applyErr := r.applyTarget(
			ctx,
			value.ID,
			targetKey,
			target,
			targetMarker,
			existing,
		)
		if applyErr != nil {
			return "", nil, applyErr
		}
		desired[targetKey] = struct{}{}

		taskMarker := ownershipMarker(settings.InstallationID, value.ID, taskKey)
		task := gmp.Task{
			Name:         targetPlan.TaskName,
			Comment:      taskMarker,
			ConfigID:     value.EffectiveScanConfig(settings).ID,
			TargetID:     targetResource.GVMID,
			ScannerID:    value.EffectiveScanner(settings).ID,
			ScheduleID:   scheduleResource.GVMID,
			ScheduleRuns: 0,
		}
		if _, applyErr := r.applyTask(
			ctx,
			value.ID,
			taskKey,
			task,
			taskMarker,
			existing,
		); applyErr != nil {
			return "", nil, applyErr
		}
		desired[taskKey] = struct{}{}
	}
	return scheduleResource.GVMID, desired, nil
}

func (r *Reconciler) applySchedule(
	ctx context.Context,
	customerID string,
	resourceKey resourceKey,
	value gmp.Schedule,
	marker string,
	existing map[resourceKey]store.ManagedResource,
) (store.ManagedResource, error) {
	hash := desiredHash(value)
	return r.applyResource(
		ctx,
		customerID,
		resourceKey,
		marker,
		hash,
		existing,
		func() (string, error) { return r.greenbone.CreateSchedule(ctx, value) },
		func(resourceID string) error { return r.greenbone.ModifySchedule(ctx, resourceID, value) },
		value.Name,
	)
}

func (r *Reconciler) applyTarget(
	ctx context.Context,
	customerID string,
	resourceKey resourceKey,
	value gmp.Target,
	marker string,
	existing map[resourceKey]store.ManagedResource,
) (store.ManagedResource, error) {
	hash := desiredHash(value)
	return r.applyResource(
		ctx,
		customerID,
		resourceKey,
		marker,
		hash,
		existing,
		func() (string, error) { return r.greenbone.CreateTarget(ctx, value) },
		func(resourceID string) error { return r.greenbone.ModifyTarget(ctx, resourceID, value) },
		value.Name,
	)
}

func (r *Reconciler) applyTask(
	ctx context.Context,
	customerID string,
	resourceKey resourceKey,
	value gmp.Task,
	marker string,
	existing map[resourceKey]store.ManagedResource,
) (store.ManagedResource, error) {
	hash := desiredHash(value)
	if err := r.replaceChangedTask(ctx, customerID, resourceKey, hash, existing); err != nil {
		return store.ManagedResource{}, err
	}
	return r.applyResource(
		ctx,
		customerID,
		resourceKey,
		marker,
		hash,
		existing,
		func() (string, error) { return r.greenbone.CreateTask(ctx, value) },
		func(resourceID string) error { return r.greenbone.ModifyTask(ctx, resourceID, value) },
		value.Name,
	)
}

func (r *Reconciler) releaseTaskForTargetChange(
	ctx context.Context,
	customerID string,
	targetKey,
	taskKey resourceKey,
	desiredTargetHash string,
	existing map[resourceKey]store.ManagedResource,
) error {
	targetResource, found := existing[targetKey]
	if !found || targetResource.GVMID == "" ||
		(targetResource.State == "applied" && targetResource.DesiredHash == desiredTargetHash) {
		return nil
	}
	return r.removeManagedTask(ctx, customerID, taskKey, existing)
}

func (r *Reconciler) replaceChangedTask(
	ctx context.Context,
	customerID string,
	taskKey resourceKey,
	desiredTaskHash string,
	existing map[resourceKey]store.ManagedResource,
) error {
	resource, found := existing[taskKey]
	if !found || resource.DesiredHash == desiredTaskHash {
		return nil
	}
	return r.removeManagedTask(ctx, customerID, taskKey, existing)
}

func (r *Reconciler) removeManagedTask(
	ctx context.Context,
	customerID string,
	taskKey resourceKey,
	existing map[resourceKey]store.ManagedResource,
) error {
	resource, found := existing[taskKey]
	if !found {
		return nil
	}
	if resource.GVMID == "" {
		resourceID, recovered, err := r.greenbone.FindResource(
			ctx,
			"task",
			resource.OwnershipMarker,
		)
		if err != nil {
			return err
		}
		if recovered {
			resource.GVMID = resourceID
		}
	}
	if err := r.deleteResource(ctx, resource); err != nil {
		return err
	}
	if err := r.repository.DeleteManagedResource(
		ctx,
		customerID,
		taskKey.kind,
		taskKey.class,
		taskKey.sequence,
	); err != nil {
		return err
	}
	delete(existing, taskKey)
	return nil
}

func (r *Reconciler) applyResource(
	ctx context.Context,
	customerID string,
	resourceKey resourceKey,
	marker,
	hash string,
	existing map[resourceKey]store.ManagedResource,
	create func() (string, error),
	modify func(resourceID string) error,
	resourceName string,
) (result store.ManagedResource, resultErr error) {
	tracker := r.trackers[customerID]
	action := "unchanged"
	started := time.Now()
	if tracker != nil {
		started = tracker.begin(ctx, "reconcile", resourceKey.kind, resourceName)
		defer func() {
			tracker.finish(ctx, started, action, resourceKey.kind, resourceName, resultErr)
		}()
	}
	resource, found := existing[resourceKey]
	if found && resource.GVMID != "" && resource.DesiredHash == hash && resource.State == "applied" {
		return resource, nil
	}
	hadCheckpoint := found
	if !found {
		resource = managedResource(
			customerID,
			resourceKey,
			"",
			hash,
			marker,
			"creating",
			"",
		)
		if err := r.repository.UpsertManagedResource(ctx, resource); err != nil {
			return store.ManagedResource{}, err
		}
		existing[resourceKey] = resource
		found = true
	}

	action = "created"
	if hadCheckpoint && resource.GVMID == "" {
		resourceID, recovered, err := r.greenbone.FindResource(ctx, resourceKey.kind, marker)
		if err != nil {
			return store.ManagedResource{}, err
		}
		if recovered {
			resource.GVMID = resourceID
			action = "recovered"
		}
	}
	if found && resource.GVMID != "" {
		owned, err := r.isOwned(ctx, resource, marker)
		if err != nil && !errors.Is(err, gmp.ErrNotFound) {
			return store.ManagedResource{}, err
		}
		if owned {
			if err := modify(resource.GVMID); err != nil {
				return store.ManagedResource{}, r.recordResourceError(ctx, resource, err)
			}
			action = "modified"
		} else if err == nil {
			return store.ManagedResource{}, ErrOwnershipMismatch
		} else {
			resource.GVMID = ""
		}
	}
	if resource.GVMID == "" {
		resourceID, err := create()
		if err != nil {
			resource = managedResource(customerID, resourceKey, "", hash, marker, "error", err.Error())
			return store.ManagedResource{}, r.recordResourceError(ctx, resource, err)
		}
		resource.GVMID = resourceID
	}

	resource = managedResource(customerID, resourceKey, resource.GVMID, hash, marker, "applied", "")
	if err := r.repository.UpsertManagedResource(ctx, resource); err != nil {
		return store.ManagedResource{}, err
	}
	existing[resourceKey] = resource
	if err := r.repository.AddAuditEvent(ctx, store.AuditEvent{
		CustomerID:   customerID,
		Action:       action,
		ResourceKind: resourceKey.kind,
		ResourceName: resourceName,
	}); err != nil {
		return store.ManagedResource{}, err
	}
	r.logger.Info(
		"greenbone resource reconciled",
		"customer_id", customerID,
		"resource_kind", resourceKey.kind,
		"resource_id", resource.GVMID,
		"action", action,
		"ownership_marker", marker,
	)
	return resource, nil
}

func managedResource(
	customerID string,
	resourceKey resourceKey,
	resourceID,
	hash,
	marker,
	state,
	lastError string,
) store.ManagedResource {
	return store.ManagedResource{
		CustomerID:      customerID,
		Kind:            resourceKey.kind,
		Class:           resourceKey.class,
		Sequence:        resourceKey.sequence,
		GVMID:           resourceID,
		DesiredHash:     hash,
		OwnershipMarker: marker,
		State:           state,
		LastError:       lastError,
	}
}

func (r *Reconciler) recordResourceError(
	ctx context.Context,
	resource store.ManagedResource,
	resourceErr error,
) error {
	resource.State = "error"
	resource.LastError = resourceErr.Error()
	if err := r.repository.UpsertManagedResource(ctx, resource); err != nil {
		return errors.Join(resourceErr, err)
	}
	return resourceErr
}

func (r *Reconciler) cleanupSurplus(
	ctx context.Context,
	customerID string,
	existing map[resourceKey]store.ManagedResource,
	desired map[resourceKey]struct{},
) error {
	resources := make([]store.ManagedResource, 0)
	for resourceKey, resource := range existing {
		if _, keep := desired[resourceKey]; !keep {
			resources = append(resources, resource)
		}
	}
	sortForDeletion(resources)
	for _, resource := range resources {
		if err := r.deleteResource(ctx, resource); err != nil {
			return err
		}
		if err := r.repository.DeleteManagedResource(
			ctx,
			customerID,
			resource.Kind,
			resource.Class,
			resource.Sequence,
		); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) cleanupCustomer(ctx context.Context, customerID string) error {
	resources, err := r.repository.ManagedResources(ctx, customerID)
	if err != nil {
		return err
	}
	sortForDeletion(resources)
	for _, resource := range resources {
		if err := r.deleteResource(ctx, resource); err != nil {
			return err
		}
		if err := r.repository.DeleteManagedResource(
			ctx,
			customerID,
			resource.Kind,
			resource.Class,
			resource.Sequence,
		); err != nil {
			return err
		}
	}
	return nil
}

func sortForDeletion(resources []store.ManagedResource) {
	priority := map[string]int{"task": 1, "target": 2, "schedule": 3}
	slices.SortFunc(resources, func(left, right store.ManagedResource) int {
		if priority[left.Kind] != priority[right.Kind] {
			return priority[left.Kind] - priority[right.Kind]
		}
		if left.Class != right.Class {
			return strings.Compare(left.Class, right.Class)
		}
		return right.Sequence - left.Sequence
	})
}

func (r *Reconciler) deleteResource(ctx context.Context, resource store.ManagedResource) (resultErr error) {
	tracker := r.trackers[resource.CustomerID]
	started := time.Now()
	if tracker != nil {
		started = tracker.begin(ctx, "trash", resource.Kind, resource.GVMID)
		defer func() {
			tracker.finish(ctx, started, "trashed", resource.Kind, resource.GVMID, resultErr)
		}()
	}
	if resource.GVMID == "" {
		return nil
	}
	owned, err := r.isOwned(ctx, resource, resource.OwnershipMarker)
	if errors.Is(err, gmp.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !owned {
		return ErrOwnershipMismatch
	}
	switch resource.Kind {
	case "task":
		err = r.greenbone.DeleteTask(ctx, resource.GVMID)
	case "target":
		err = r.greenbone.DeleteTarget(ctx, resource.GVMID)
	case "schedule":
		err = r.greenbone.DeleteSchedule(ctx, resource.GVMID)
	default:
		return fmt.Errorf("reconcile: unsupported resource kind %q", resource.Kind)
	}
	if err != nil {
		return r.recordResourceError(ctx, resource, err)
	}
	if err := r.repository.AddAuditEvent(ctx, store.AuditEvent{
		CustomerID:   resource.CustomerID,
		Action:       "trashed",
		ResourceKind: resource.Kind,
		ResourceName: resource.GVMID,
	}); err != nil {
		return err
	}
	r.logger.Info(
		"greenbone resource trashed",
		"customer_id", resource.CustomerID,
		"resource_kind", resource.Kind,
		"resource_id", resource.GVMID,
		"ownership_marker", resource.OwnershipMarker,
	)
	return nil
}

func (r *Reconciler) isOwned(
	ctx context.Context,
	resource store.ManagedResource,
	marker string,
) (bool, error) {
	comment, err := r.greenbone.ResourceComment(ctx, resource.Kind, resource.GVMID)
	if err != nil {
		return false, err
	}
	return strings.Contains(comment, marker), nil
}

func ownershipMarker(installationID, customerID string, resourceKey resourceKey) string {
	return fmt.Sprintf(
		"openvasconf:v1;installation=%s;customer=%s;kind=%s;class=%s;sequence=%d",
		installationID,
		customerID,
		resourceKey.kind,
		resourceKey.class,
		resourceKey.sequence,
	)
}

func desiredHash(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("reconcile: hashing unsupported value: %v", err))
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func gmpHostSpecifications(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}

	ordered := slices.Clone(prefixes)
	slices.SortFunc(ordered, func(left, right netip.Prefix) int {
		if compared := left.Addr().Compare(right.Addr()); compared != 0 {
			return compared
		}
		return left.Bits() - right.Bits()
	})
	result := make([]string, 0, len(prefixes))
	start := ordered[0].Addr()
	end := prefixEnd(ordered[0])
	for _, prefix := range ordered[1:] {
		currentStart := prefix.Addr()
		currentEnd := prefixEnd(prefix)
		next := end.Next()
		if currentStart.Compare(end) <= 0 || (next.IsValid() && currentStart == next) {
			if currentEnd.Compare(end) > 0 {
				end = currentEnd
			}
			continue
		}
		result = append(result, gmpHostRange(start, end))
		start, end = currentStart, currentEnd
	}
	return append(result, gmpHostRange(start, end))
}

func prefixEnd(prefix netip.Prefix) netip.Addr {
	address := prefix.Masked().Addr().As4()
	start := binary.BigEndian.Uint32(address[:])
	hostMask := ^uint32(0) >> prefix.Bits()
	binary.BigEndian.PutUint32(address[:], start|hostMask)
	return netip.AddrFrom4(address)
}

func gmpHostRange(start, end netip.Addr) string {
	if start == end {
		return start.String()
	}
	return start.String() + "-" + end.String()
}

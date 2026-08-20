package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
	"openvasconf/internal/id"
	"openvasconf/internal/networkplan"
	"openvasconf/internal/store"
)

func TestReconcilerLifecycle(t *testing.T) {
	t.Parallel()

	repository := testRepository(t)
	settings := configuredSettings(t, repository)
	value := createCustomer(
		t,
		repository,
		"testcomp1",
		[]string{"10.1.0.0/16", "192.168.10.0", "7.7.7.7/32"},
	)
	greenbone := newFakeGreenbone()
	reconciler := New(
		repository,
		greenbone,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Minute,
	)

	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(first) error = %v", err)
	}
	if got := greenbone.operationCount("create schedule"); got != 1 {
		t.Errorf("schedule creates = %d, want 1", got)
	}
	if got := greenbone.operationCount("create target"); got != 19 {
		t.Errorf("target creates = %d, want 19", got)
	}
	if got := greenbone.operationCount("create task"); got != 19 {
		t.Errorf("task creates = %d, want 19", got)
	}
	resources, err := repository.ManagedResources(t.Context(), value.ID)
	if err != nil {
		t.Fatalf("ManagedResources() error = %v", err)
	}
	if len(resources) != 39 {
		t.Fatalf("managed resource count = %d, want 39", len(resources))
	}

	greenbone.operations = []string{}
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(second) error = %v", err)
	}
	if len(greenbone.operations) != 0 {
		t.Errorf("idempotent run operations = %v, want none", greenbone.operations)
	}

	value, err = repository.Customer(t.Context(), value.ID)
	if err != nil {
		t.Fatalf("Customer() error = %v", err)
	}
	value.Networks = networks(t, value.ID, value.Name, []string{"10.0.0.1"})
	if err := repository.UpdateCustomer(t.Context(), value); err != nil {
		t.Fatalf("UpdateCustomer() error = %v", err)
	}
	greenbone.operations = []string{}
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(shrink) error = %v", err)
	}
	if greenbone.operationCount("modify target") != 1 {
		t.Errorf("shrink operations = %v", greenbone.operations)
	}
	firstTaskDelete := operationIndex(greenbone.operations, "delete task")
	targetModify := operationIndex(greenbone.operations, "modify target")
	if firstTaskDelete < 0 || targetModify < 0 || firstTaskDelete > targetModify {
		t.Errorf("task was not released before target update: %v", greenbone.operations)
	}
	firstTargetDelete := operationIndex(greenbone.operations, "delete target")
	lastTaskDelete := lastOperationIndex(greenbone.operations, "delete task")
	if firstTargetDelete < 0 || lastTaskDelete < 0 || lastTaskDelete > firstTargetDelete {
		t.Errorf("resources not deleted task-first: %v", greenbone.operations)
	}

	if err := repository.SoftDeleteCustomer(t.Context(), value.ID); err != nil {
		t.Fatalf("SoftDeleteCustomer() error = %v", err)
	}
	greenbone.operations = []string{}
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(delete) error = %v", err)
	}
	wantOrder := []string{"delete task", "delete target", "delete schedule"}
	if len(greenbone.operations) != len(wantOrder) {
		t.Fatalf("delete operations = %v, want %v", greenbone.operations, wantOrder)
	}
	for index, expected := range wantOrder {
		if !strings.HasPrefix(greenbone.operations[index], expected) {
			t.Errorf("operation %d = %q, want prefix %q", index, greenbone.operations[index], expected)
		}
	}
	resources, err = repository.ManagedResources(t.Context(), value.ID)
	if err != nil {
		t.Fatalf("ManagedResources(after delete) error = %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("managed resources after deletion = %d, want 0", len(resources))
	}
	deleted, err := repository.Customer(t.Context(), value.ID)
	if err != nil {
		t.Fatalf("Customer(deleted) error = %v", err)
	}
	if deleted.ReconciliationStatus != "deleted" {
		t.Errorf("deleted status = %q, want deleted", deleted.ReconciliationStatus)
	}
	if settings.InstallationID == "" {
		t.Error("installation id is empty")
	}
}

func TestReconcilerRefusesForeignResource(t *testing.T) {
	t.Parallel()

	repository := testRepository(t)
	configuredSettings(t, repository)
	value := createCustomer(t, repository, "ownership", []string{"10.0.0.1"})
	greenbone := newFakeGreenbone()
	reconciler := New(
		repository,
		greenbone,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Minute,
	)
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(first) error = %v", err)
	}

	resources, err := repository.ManagedResources(t.Context(), value.ID)
	if err != nil {
		t.Fatalf("ManagedResources() error = %v", err)
	}
	for _, resource := range resources {
		if resource.Kind == "target" {
			greenbone.comments[resource.Kind+":"+resource.GVMID] = "foreign owner"
		}
	}
	value, err = repository.Customer(t.Context(), value.ID)
	if err != nil {
		t.Fatalf("Customer() error = %v", err)
	}
	value.Networks = networks(t, value.ID, value.Name, []string{"10.0.0.2"})
	if err := repository.UpdateCustomer(t.Context(), value); err != nil {
		t.Fatalf("UpdateCustomer() error = %v", err)
	}
	greenbone.operations = []string{}
	err = reconciler.RunOnce(t.Context())
	if err == nil || !strings.Contains(err.Error(), ErrOwnershipMismatch.Error()) {
		t.Fatalf("RunOnce(foreign) error = %v, want ownership mismatch", err)
	}
	if greenbone.operationCount("modify target") != 0 || greenbone.operationCount("delete target") != 0 {
		t.Errorf("foreign resource changed: %v", greenbone.operations)
	}
}

func TestReconcilerResumesAfterInterruptedCreate(t *testing.T) {
	t.Parallel()

	repository := testRepository(t)
	configuredSettings(t, repository)
	createCustomer(
		t,
		repository,
		"resumable",
		[]string{"10.1.0.0/16", "7.7.7.7"},
	)
	greenbone := newFakeGreenbone()
	greenbone.failTaskCreate = 1
	reconciler := New(
		repository,
		greenbone,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Minute,
	)

	if err := reconciler.RunOnce(t.Context()); err == nil {
		t.Fatal("RunOnce(interrupted) error = nil, want injected failure")
	}
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(resume) error = %v", err)
	}
	if got := greenbone.operationCount("create schedule"); got != 1 {
		t.Errorf("schedule creates = %d, want 1", got)
	}
	if got := greenbone.operationCount("create target"); got != 19 {
		t.Errorf("target creates = %d, want 19", got)
	}
	if got := greenbone.operationCount("create task"); got != 19 {
		t.Errorf("task creates = %d, want 19", got)
	}
}

func TestReconcilerRecoversRemoteObjectAfterCheckpointLoss(t *testing.T) {
	t.Parallel()

	repository := testRepository(t)
	settings := configuredSettings(t, repository)
	value := createCustomer(t, repository, "checkpoint", []string{"10.0.0.1"})
	greenbone := newFakeGreenbone()
	scheduleKey := key("schedule", "", 0)
	marker := ownershipMarker(settings.InstallationID, value.ID, scheduleKey)
	remoteScheduleID := greenbone.create(
		"schedule",
		"checkpoint_Weekly_Schedule",
		marker,
	)
	if err := repository.UpsertManagedResource(t.Context(), managedResource(
		value.ID,
		scheduleKey,
		"",
		"interrupted-hash",
		marker,
		"creating",
		"",
	)); err != nil {
		t.Fatalf("UpsertManagedResource() error = %v", err)
	}
	greenbone.operations = nil
	reconciler := New(
		repository,
		greenbone,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Minute,
	)

	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if got := greenbone.operationCount("create schedule"); got != 0 {
		t.Errorf("schedule creates = %d, want 0", got)
	}
	resources, err := repository.ManagedResources(t.Context(), value.ID)
	if err != nil {
		t.Fatalf("ManagedResources() error = %v", err)
	}
	for _, resource := range resources {
		if resource.Kind == "schedule" && resource.GVMID != remoteScheduleID {
			t.Errorf("schedule id = %q, want recovered %q", resource.GVMID, remoteScheduleID)
		}
	}
}

func TestReconcilerAppliesGlobalDefaultsAndCustomerOverrides(t *testing.T) {
	t.Parallel()

	repository := testRepository(t)
	settings := configuredSettings(t, repository)
	value := createCustomer(t, repository, "overrides", []string{"10.0.0.1"})
	greenbone := newFakeGreenbone()
	reconciler := New(
		repository,
		greenbone,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Minute,
	)
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(initial) error = %v", err)
	}

	settings.Scanner = customer.Selection{ID: "global-scanner-2", Name: "Global Scanner 2"}
	settings.ScanConfig = customer.Selection{ID: "global-config-2", Name: "Global Config 2"}
	if err := repository.UpdateSettings(t.Context(), settings); err != nil {
		t.Fatalf("UpdateSettings(global) error = %v", err)
	}
	greenbone.operations = nil
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(global) error = %v", err)
	}
	if greenbone.operationCount("modify target") != 0 ||
		greenbone.operationCount("delete task") != 1 ||
		greenbone.operationCount("create task") != 1 {
		t.Errorf("global default operations = %v", greenbone.operations)
	}

	value, err := repository.Customer(t.Context(), value.ID)
	if err != nil {
		t.Fatalf("Customer() error = %v", err)
	}
	value.ScannerID, value.ScannerName = "customer-scanner", "Customer Scanner"
	value.ScanConfigID, value.ScanConfigName = "customer-config", "Customer Config"
	value.PortListID, value.PortListName = "customer-ports", "Customer Ports"
	if err := repository.UpdateCustomer(t.Context(), value); err != nil {
		t.Fatalf("UpdateCustomer(overrides) error = %v", err)
	}
	greenbone.operations = nil
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(overrides) error = %v", err)
	}
	if greenbone.operationCount("modify target") != 1 ||
		greenbone.operationCount("delete task") != 1 ||
		greenbone.operationCount("create task") != 1 {
		t.Errorf("customer override operations = %v", greenbone.operations)
	}

	settings.Scanner = customer.Selection{ID: "global-scanner-3", Name: "Global Scanner 3"}
	settings.ScanConfig = customer.Selection{ID: "global-config-3", Name: "Global Config 3"}
	settings.PortList = customer.Selection{ID: "global-ports-3", Name: "Global Ports 3"}
	if err := repository.UpdateSettings(t.Context(), settings); err != nil {
		t.Fatalf("UpdateSettings(after overrides) error = %v", err)
	}
	greenbone.operations = nil
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce(after overrides) error = %v", err)
	}
	if len(greenbone.operations) != 0 {
		t.Errorf("global change bypassed overrides: %v", greenbone.operations)
	}
}

func TestWeeklyCalendar(t *testing.T) {
	t.Parallel()

	value := customer.Customer{
		ID:              "customer-id",
		Name:            "A, B; C",
		ScheduleWeekday: 4,
		ScheduleMinute:  8*60 + 15,
	}
	calendar := weeklyCalendar(value)
	for _, expected := range []string{
		"DTSTART:20240104T081500",
		"RRULE:FREQ=WEEKLY;BYDAY=TH",
		`SUMMARY:A\, B\; C vulnerability scan`,
	} {
		if !strings.Contains(calendar, expected) {
			t.Errorf("calendar does not contain %q:\n%s", expected, calendar)
		}
	}
}

func TestPrefixStringsFormatsHostsForGMP(t *testing.T) {
	t.Parallel()

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/24"),
		netip.MustParsePrefix("192.168.10.0/32"),
		netip.MustParsePrefix("7.7.7.7/32"),
	}
	want := []string{"10.1.0.0/24", "192.168.10.0", "7.7.7.7"}
	if got := prefixStrings(prefixes); !slices.Equal(got, want) {
		t.Errorf("prefixStrings() = %v, want %v", got, want)
	}
}

func TestRetryTransient(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := retryTransient(t.Context(), 3, time.Millisecond, func() error {
		attempts++
		if attempts < 3 {
			return &gmp.ProtocolError{Status: "503", StatusText: "temporarily unavailable"}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retryTransient() error = %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestRetryTransientDoesNotRetryPermanentError(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := retryTransient(t.Context(), 3, time.Millisecond, func() error {
		attempts++
		return &gmp.ProtocolError{Status: "400", StatusText: "invalid request"}
	})
	if err == nil {
		t.Fatal("retryTransient() error = nil, want protocol error")
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}

func TestRetryTransientHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	attempts := 0
	err := retryTransient(ctx, 3, time.Hour, func() error {
		attempts++
		cancel()
		return &gmp.ProtocolError{Status: "503", StatusText: "temporarily unavailable"}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("retryTransient() error = %v, want context canceled", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}

func testRepository(t *testing.T) *store.Store {
	t.Helper()
	repository, err := store.Open(
		t.Context(),
		filepath.Join(t.TempDir(), "reconcile.db"),
		"Europe/Vienna",
	)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	return repository
}

func configuredSettings(t *testing.T, repository *store.Store) customer.Settings {
	t.Helper()
	settings, err := repository.Settings(t.Context())
	if err != nil {
		t.Fatalf("Settings() error = %v", err)
	}
	settings.Scanner = customer.Selection{ID: "scanner-id", Name: "OpenVAS Default"}
	settings.ScanConfig = customer.Selection{ID: "config-id", Name: "Full and fast"}
	settings.PortList = customer.Selection{ID: "port-list-id", Name: "All IANA assigned TCP"}
	if err := repository.UpdateSettings(t.Context(), settings); err != nil {
		t.Fatalf("UpdateSettings() error = %v", err)
	}
	return settings
}

func createCustomer(
	t *testing.T,
	repository *store.Store,
	name string,
	inputs []string,
) customer.Customer {
	t.Helper()
	customerID, err := id.New()
	if err != nil {
		t.Fatalf("id.New() error = %v", err)
	}
	value := customer.Customer{
		ID:              customerID,
		Name:            name,
		SafeName:        networkplan.SafeName(name),
		ScheduleWeekday: 2,
		ScheduleMinute:  9 * 60,
		Timezone:        "Europe/Vienna",
		Networks:        networks(t, customerID, name, inputs),
	}
	if err := repository.CreateCustomer(t.Context(), value); err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	return value
}

func networks(t *testing.T, customerID, name string, inputs []string) []customer.Network {
	t.Helper()
	result := make([]customer.Network, 0, len(inputs))
	for _, input := range inputs {
		prefix, err := networkplan.Parse(input)
		if err != nil {
			t.Fatalf("networkplan.Parse(%q) error = %v", input, err)
		}
		plan, err := networkplan.Build(networkplan.Input{
			CustomerName: name,
			Networks:     []string{input},
		})
		if err != nil {
			t.Fatalf("networkplan.Build(%q) error = %v", input, err)
		}
		networkID, err := id.New()
		if err != nil {
			t.Fatalf("id.New() error = %v", err)
		}
		result = append(result, customer.Network{
			ID:         networkID,
			CustomerID: customerID,
			Input:      input,
			Prefix:     prefix.String(),
			Class:      string(plan.Targets[0].Class),
		})
	}
	return result
}

func operationIndex(operations []string, prefix string) int {
	for index, operation := range operations {
		if strings.HasPrefix(operation, prefix) {
			return index
		}
	}
	return -1
}

func lastOperationIndex(operations []string, prefix string) int {
	for index := len(operations) - 1; index >= 0; index-- {
		if strings.HasPrefix(operations[index], prefix) {
			return index
		}
	}
	return -1
}

type fakeGreenbone struct {
	nextID         int
	taskCreates    int
	failTaskCreate int
	comments       map[string]string
	operations     []string
}

func newFakeGreenbone() *fakeGreenbone {
	return &fakeGreenbone{
		comments:   make(map[string]string),
		operations: []string{},
	}
}

func (f *fakeGreenbone) Ping(context.Context) (string, error) {
	return "22.4", nil
}

func (f *fakeGreenbone) Options(context.Context) (gmp.Options, error) {
	return gmp.Options{}, nil
}

func (f *fakeGreenbone) CreateSchedule(_ context.Context, value gmp.Schedule) (string, error) {
	return f.create("schedule", value.Name, value.Comment), nil
}

func (f *fakeGreenbone) ModifySchedule(_ context.Context, id string, value gmp.Schedule) error {
	return f.modify("schedule", id, value.Name, value.Comment)
}

func (f *fakeGreenbone) DeleteSchedule(_ context.Context, id string) error {
	return f.delete("schedule", id)
}

func (f *fakeGreenbone) CreateTarget(_ context.Context, value gmp.Target) (string, error) {
	return f.create("target", value.Name, value.Comment), nil
}

func (f *fakeGreenbone) ModifyTarget(_ context.Context, id string, value gmp.Target) error {
	return f.modify("target", id, value.Name, value.Comment)
}

func (f *fakeGreenbone) DeleteTarget(_ context.Context, id string) error {
	return f.delete("target", id)
}

func (f *fakeGreenbone) CreateTask(_ context.Context, value gmp.Task) (string, error) {
	f.taskCreates++
	resourceID := f.create("task", value.Name, value.Comment)
	if f.taskCreates == f.failTaskCreate {
		return "", errors.New("injected lost create task response")
	}
	return resourceID, nil
}

func (f *fakeGreenbone) ModifyTask(_ context.Context, id string, value gmp.Task) error {
	return f.modify("task", id, value.Name, value.Comment)
}

func (f *fakeGreenbone) DeleteTask(_ context.Context, id string) error {
	return f.delete("task", id)
}

func (f *fakeGreenbone) ResourceComment(_ context.Context, kind, id string) (string, error) {
	comment, found := f.comments[kind+":"+id]
	if !found {
		return "", gmp.ErrNotFound
	}
	return comment, nil
}

func (f *fakeGreenbone) FindResource(
	_ context.Context,
	kind,
	ownershipMarker string,
) (string, bool, error) {
	for resourceKey, comment := range f.comments {
		if strings.HasPrefix(resourceKey, kind+":") && strings.Contains(comment, ownershipMarker) {
			return strings.TrimPrefix(resourceKey, kind+":"), true, nil
		}
	}
	return "", false, nil
}

func (f *fakeGreenbone) create(kind, name, comment string) string {
	f.nextID++
	id := fmt.Sprintf("%s-%d", kind, f.nextID)
	f.comments[kind+":"+id] = comment
	f.operations = append(f.operations, "create "+kind+" "+name)
	return id
}

func (f *fakeGreenbone) modify(kind, id, name, comment string) error {
	if _, found := f.comments[kind+":"+id]; !found {
		return gmp.ErrNotFound
	}
	f.comments[kind+":"+id] = comment
	f.operations = append(f.operations, "modify "+kind+" "+name)
	return nil
}

func (f *fakeGreenbone) delete(kind, id string) error {
	if _, found := f.comments[kind+":"+id]; !found {
		return gmp.ErrNotFound
	}
	delete(f.comments, kind+":"+id)
	f.operations = append(f.operations, "delete "+kind+" "+id)
	return nil
}

func (f *fakeGreenbone) operationCount(prefix string) int {
	count := 0
	for _, operation := range f.operations {
		if strings.HasPrefix(operation, prefix) {
			count++
		}
	}
	return count
}

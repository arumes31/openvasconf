package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openvasconf/internal/auth"
	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
)

type fakeTaskControlGreenbone struct {
	fakeGreenbone
	stopped  []string
	tasks    []gmp.TaskStatus
	comments map[string]string
}

func (f *fakeTaskControlGreenbone) Feeds(context.Context) ([]gmp.Feed, error) {
	return []gmp.Feed{{Type: "NVT", Name: "test feed"}}, nil
}

func (f *fakeTaskControlGreenbone) Tasks(context.Context) ([]gmp.TaskStatus, error) {
	return f.tasks, nil
}

func (f *fakeTaskControlGreenbone) StartTask(_ context.Context, taskID string) (string, error) {
	return "report-1", nil
}

func (f *fakeTaskControlGreenbone) StopTask(_ context.Context, taskID string) error {
	f.stopped = append(f.stopped, taskID)
	return nil
}

func (f *fakeTaskControlGreenbone) InspectResource(
	_ context.Context,
	_,
	resourceID string,
) (gmp.ResourceDetails, error) {
	return gmp.ResourceDetails{ID: resourceID, Comment: f.comments[resourceID]}, nil
}

func newTaskControlApp(t *testing.T, greenbone *fakeTaskControlGreenbone) testWebApp {
	t.Helper()
	repository, err := store.Open(
		context.Background(),
		filepath.Join(t.TempDir(), "openvasconf.db"),
		"Europe/Vienna",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })

	authenticator := auth.New(repository, time.Hour)
	if err := authenticator.Bootstrap(context.Background(), testAdminPassword); err != nil {
		t.Fatal(err)
	}
	syncer := &triggerCounter{}
	application, err := New(Options{
		Repository: repository,
		Auth:       authenticator,
		Greenbone:  greenbone,
		Syncer:     syncer,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return testWebApp{
		server:     server,
		client:     &http.Client{Jar: jar},
		repository: repository,
		syncer:     syncer,
	}
}

func seedManagedTask(t *testing.T, app testWebApp, marker string) customer.Customer {
	t.Helper()
	value := customer.Customer{
		ID:              "customer-task-control",
		Name:            "taskcontrol",
		SafeName:        "taskcontrol",
		ScheduleWeekday: 2,
		ScheduleMinute:  600,
		Timezone:        "Europe/Vienna",
		Networks: []customer.Network{{
			ID:         "network-1",
			CustomerID: "customer-task-control",
			Input:      "10.9.0.1",
			Prefix:     "10.9.0.1/32",
			Class:      "PrivateIP",
		}},
	}
	if err := app.repository.CreateCustomer(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if err := app.repository.UpsertManagedResource(context.Background(), store.ManagedResource{
		CustomerID:      value.ID,
		Kind:            "task",
		Class:           "PrivateIP",
		Sequence:        1,
		GVMID:           "gvm-task-1",
		OwnershipMarker: marker,
		State:           "applied",
	}); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestStopRunningTask(t *testing.T) {
	marker := "openvasconf:v1;customer=customer-task-control"
	greenbone := &fakeTaskControlGreenbone{
		fakeGreenbone: fakeGreenbone{options: testOptions()},
		tasks: []gmp.TaskStatus{{
			ID: "gvm-task-1", Name: "taskcontrol_PrivateIP_Task1", Status: "Running", Progress: 42,
		}},
		comments: map[string]string{"gvm-task-1": marker},
	}
	app := newTaskControlApp(t, greenbone)
	created := seedManagedTask(t, app, marker)
	login(t, app)

	editResponse, err := app.client.Get(app.server.URL + "/customers/" + created.ID)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, editResponse)
	if !strings.Contains(body, "Stop scan") {
		t.Fatalf("edit page does not offer stop for a running task")
	}

	response := postForm(t, app, "/customers/"+created.ID+"/tasks/task/PrivateIP/1/stop", nil)
	body = readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("stop final status = %d: %s", response.StatusCode, body)
	}
	if len(greenbone.stopped) != 1 || greenbone.stopped[0] != "gvm-task-1" {
		t.Fatalf("stopped tasks = %v, want gvm-task-1", greenbone.stopped)
	}
	if !strings.Contains(body, "Stop requested") {
		t.Fatalf("stop notice missing from page")
	}
}

func TestStopRejectsForeignTask(t *testing.T) {
	greenbone := &fakeTaskControlGreenbone{
		fakeGreenbone: fakeGreenbone{options: testOptions()},
		comments:      map[string]string{"gvm-task-1": "someone else owns this"},
	}
	app := newTaskControlApp(t, greenbone)
	created := seedManagedTask(t, app, "openvasconf:v1;customer=customer-task-control")
	login(t, app)

	response := postForm(t, app, "/customers/"+created.ID+"/tasks/task/PrivateIP/1/stop", nil)
	_ = readBody(t, response)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("foreign stop status = %d, want %d", response.StatusCode, http.StatusConflict)
	}
	if len(greenbone.stopped) != 0 {
		t.Fatalf("foreign task was stopped: %v", greenbone.stopped)
	}
}

func TestHealthStripRenderedOnAuthenticatedPages(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)

	response, err := app.client.Get(app.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	for _, expected := range []string{"health-strip", "health-green", "All systems healthy", "Database", "Greenbone", "Reconciliation"} {
		if !strings.Contains(body, expected) {
			t.Errorf("dashboard health strip misses %q", expected)
		}
	}
}

func TestHealthStripAmberOnReconciliationError(t *testing.T) {
	app := newTestWebApp(t)
	created := seedManagedTask(t, app, "marker")
	if err := app.repository.SetCustomerReconciliation(
		context.Background(), created.ID, "error", "boom",
	); err != nil {
		t.Fatal(err)
	}
	login(t, app)

	response, err := app.client.Get(app.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, response)
	if !strings.Contains(body, "health-amber") {
		t.Fatalf("dashboard health strip is not amber:\n%s", body)
	}
	if !strings.Contains(body, "Reconciliation degraded") {
		t.Errorf("health summary does not name the degraded component")
	}
}

func testOptions() gmp.Options {
	return gmp.Options{
		Scanners:    []gmp.Option{{ID: "scanner-1", Name: "OpenVAS Default"}},
		ScanConfigs: []gmp.Option{{ID: "config-1", Name: "Full and fast"}},
		PortLists:   []gmp.Option{{ID: "ports-1", Name: "All IANA assigned TCP"}},
	}
}
